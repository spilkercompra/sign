// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Cli.SignatureProviders
{
    using eEvolution.Sign.JSign;
    using global::Sign.Core;
    using Microsoft.Extensions.Logging;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    public class JSignSignatureProvider : ISignatureProvider
    {
        #region Fields

        private readonly ISignatureAlgorithmProvider _signatureAlgorithmProvider;
        private readonly ICertificateProvider _certificateProvider;
        private readonly ILogger _logger;
        private readonly HashSet<string> _supportedFileExtensions;
        private readonly IToolConfigurationProvider _toolConfigurationProvider;

        #endregion Fields

        #region Constructors

        // Dependency injection requires a public constructor.
        public JSignSignatureProvider(
            IToolConfigurationProvider toolConfigurationProvider,
            ISignatureAlgorithmProvider signatureAlgorithmProvider,
            ICertificateProvider certificateProvider,
            ILogger<ISignatureProvider> logger)
        {
            ArgumentNullException.ThrowIfNull(toolConfigurationProvider, nameof(toolConfigurationProvider));
            ArgumentNullException.ThrowIfNull(signatureAlgorithmProvider, nameof(signatureAlgorithmProvider));
            ArgumentNullException.ThrowIfNull(certificateProvider, nameof(certificateProvider));
            ArgumentNullException.ThrowIfNull(logger, nameof(logger));

            _signatureAlgorithmProvider = signatureAlgorithmProvider;
            _certificateProvider = certificateProvider;
            _signatureAlgorithmProvider = signatureAlgorithmProvider;
            _logger = logger;
            _toolConfigurationProvider = toolConfigurationProvider;

            // https://github.com/ebourg/jsign/blob/31f9f89ece9a2c1dd67955aa7079ca052b0a0582/jsign/src/deb/data/usr/share/bash-completion/completions/jsign#L17
            var pattern = "exe|dll|cpl|ocx|sys|scr|drv|ps1|psm1|psd1|msi|msp|cab|cat|appx|appxbundle|msix|msixbundle|navx|app";
            _supportedFileExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var extension in pattern.Split('|'))
            {
                _supportedFileExtensions.Add($".{extension}");
            }
        }

        #endregion Constructors

        #region Methods

        public bool CanSign(FileInfo file)
        {
            ArgumentNullException.ThrowIfNull(file, nameof(file));

            return _supportedFileExtensions.Contains(file.Extension);
        }

        public async Task SignAsync(IEnumerable<FileInfo> files, SignOptions options)
        {
            ArgumentNullException.ThrowIfNull(files, nameof(files));
            ArgumentNullException.ThrowIfNull(options, nameof(options));

            _logger.LogInformation(Resources.AzureSignToolSignatureProviderSigning, files.Count());

            TimeStampConfiguration timestampConfiguration;

            if (options.TimestampService is null)
            {
                timestampConfiguration = TimeStampConfiguration.None;
            }
            else
            {
                timestampConfiguration = new(options.TimestampService.AbsoluteUri, options.TimestampHashAlgorithm, TimeStampType.RFC3161);
            }

            using (X509Certificate2 certificate = await _certificateProvider.GetCertificateAsync())
            using (RSA rsa = await _signatureAlgorithmProvider.GetRsaAsync())
            using (JSignSigner signer = new(
                rsa,
                certificate,
                options.FileHashAlgorithm,
                timestampConfiguration))
            {
                // loop through all of the files here, looking for appx/eappx
                // mark each as being signed and strip appx
                await Parallel.ForEachAsync(files, async (file, state) =>
                {
                    if (!await SignAsync(signer, file, options))
                    {
                        string message = string.Format(CultureInfo.CurrentCulture, Resources.SigningFailed, file.FullName);

                        throw new Exception(message);
                    }
                });
            }
        }

        private bool RunSignTool(JSignSigner signer, FileInfo file, SignOptions options)
        {
            ////FileInfo manifestFile = _toolConfigurationProvider.SignToolManifest;

            _logger.LogInformation(Resources.SigningFile, file.FullName);

            var success = false;
            var code = 0;
            const int S_OK = 0;

            try
            {
                ////using (var ctx = new Kernel32.ActivationContext(manifestFile))
                ////{
                code = signer.SignFile(
                    file.FullName,
                    options.Description,
                    options.DescriptionUrl?.AbsoluteUri);
                ////pageHashing: null,
                ////_logger);
                success = code == S_OK;
                ////}
            }
            catch (Exception e)
            {
                _logger.LogError(e, e.Message);
            }

            if (success)
            {
                _logger.LogInformation(Resources.SigningSucceeded);
                return true;
            }

            _logger.LogError(Resources.SigningFailedWithError, code);

            return false;
        }

        // Inspired from https://github.com/squaredup/bettersigntool/blob/master/bettersigntool/bettersigntool/SignCommand.cs
        private async Task<bool> SignAsync(
            JSignSigner signer,
            FileInfo file,
            SignOptions options)
        {
            TimeSpan retry = TimeSpan.FromSeconds(5);
            const int maxAttempts = 3;
            var attempt = 1;

            do
            {
                if (attempt > 1)
                {
                    _logger.LogInformation(Resources.SigningAttempt, attempt, maxAttempts, retry.TotalSeconds);
                    await Task.Delay(retry);
                    retry = TimeSpan.FromSeconds(Math.Pow(retry.TotalSeconds, 1.5));
                }

                if (RunSignTool(signer, file, options))
                {
                    return true;
                }

                ++attempt;
            } while (attempt <= maxAttempts);

            _logger.LogError(Resources.SigningFailedAfterAllAttempts);

            return false;
        }

        #endregion Methods
    }
}