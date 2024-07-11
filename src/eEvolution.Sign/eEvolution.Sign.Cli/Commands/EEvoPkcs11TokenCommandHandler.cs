namespace eEvolution.Sign.Cli.Commands
{
    using eEvolution.Sign.Cli.DataFormatSigners;
    using eEvolution.Sign.Cli.SignatureProviders;
    using eEvolution.Sign.Cli.Tools;
    using global::Sign.Cli;
    using global::Sign.Core;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.DependencyInjection.Extensions;
    using System;
    using System.CommandLine;
    using System.CommandLine.IO;
    using Resources = global::Sign.Cli.Resources;

    internal static class EEvoPkcs11TokenCommandHandler
    {
        #region Methods

        internal static void SetupEEvoPkcs11TokenCommand(Command eevoPkcs11TokenCommand, CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory, EEvoPkcs11TokenCommandHandlerOptions options)
        {
            ArgumentNullException.ThrowIfNull(codeCommand, nameof(codeCommand));
            ArgumentNullException.ThrowIfNull(serviceProviderFactory, nameof(serviceProviderFactory));

            options.UrlOption.IsRequired = true;
            options.CertificateOption.IsRequired = true;

            options.CredentialOptions.TenantIdOption.IsRequired = true;
            options.CredentialOptions.ClientIdOption.IsRequired = true;
            options.CredentialOptions.ClientSecretOption.IsRequired = true;
            options.CredentialOptions.TenantIdOption.IsHidden = false;
            options.CredentialOptions.ClientIdOption.IsHidden = false;
            options.CredentialOptions.ClientSecretOption.IsHidden = false;

            eevoPkcs11TokenCommand.AddOption(options.UrlOption);
            eevoPkcs11TokenCommand.AddOption(options.CertificateOption);
            eevoPkcs11TokenCommand.AddOption(options.CredentialOptions.TenantIdOption);
            eevoPkcs11TokenCommand.AddOption(options.CredentialOptions.ClientIdOption);
            eevoPkcs11TokenCommand.AddOption(options.CredentialOptions.ClientSecretOption);

            eevoPkcs11TokenCommand.AddArgument(options.FileArgument);

            eevoPkcs11TokenCommand.SetHandler(async (context) =>
            {
                string? fileArgument = context.ParseResult.GetValueForArgument(options.FileArgument);

                if (string.IsNullOrEmpty(fileArgument))
                {
                    context.Console.Error.WriteLine(Resources.MissingFileValue);
                    context.ExitCode = ExitCode.InvalidOptions;
                    return;
                }

                // this check exists as a courtesy to users who may have been signing .clickonce files via the old workaround.
                // at some point we should remove this check, probably once we hit v1.0
                if (fileArgument.EndsWith(".clickonce", StringComparison.OrdinalIgnoreCase))
                {
                    context.Console.Error.WriteLine(AzureKeyVaultResources.ClickOnceExtensionNotSupported);
                    context.ExitCode = ExitCode.InvalidOptions;
                    return;
                }

                // Some of the options are required and that is why we can safely use
                // the null-forgiving operator (!) to simplify the code.
                Uri url = context.ParseResult.GetValueForOption(options.UrlOption)!;
                string certificateId = context.ParseResult.GetValueForOption(options.CertificateOption)!;

                var tenantId = context.ParseResult.GetValueForOption(options.CredentialOptions.TenantIdOption)!;
                var clientId = context.ParseResult.GetValueForOption(options.CredentialOptions.ClientIdOption)!;
                var secret = context.ParseResult.GetValueForOption(options.CredentialOptions.ClientSecretOption)!;

                var useJSign = context.ParseResult.GetValueForOption(options.UseJSignOption) ?? true;
                var wrappedServiceProviderFactory = new ServiceProviderFactoryWrapper(serviceProviderFactory);
                wrappedServiceProviderFactory.AfterAddServices = (IServiceCollection services) =>
                  {
                      // Jsign statt AzureSignToolSignatureProvider
                      // TODO: ggf. mit neuem Aggregator nur die nicht unterstützten Dateitypen austauschen.
                      // Vorteile derzeit: Läuft auf unserem Buildserver unter unter Windows 8, unterstützt das Append von Signaturen oder skippen von bereits signierten Files.
                      if (useJSign)
                      {
                          services.ReplaceExact(
                              ServiceDescriptor.Singleton<IDataFormatSigner, AzureSignToolSigner>(),
                              ServiceDescriptor.Singleton<IDataFormatSigner, JSignDataFormatSigner>());

                          services.Replace(
                              ServiceDescriptor.Singleton<
                                IDefaultDataFormatSigner,
                                DefaultDataFormatSigner<JSignDataFormatSigner>>());
                      }
                  };

                var eevoPkcs11ServiceProvider = new EEvoPkcs11ServiceProvider(
                   useLocalClient: options.UseLocalClient,
                   keyVaultUrl: url,
                   tokenCredential: (tenantId, clientId, secret),
                   certificateId);
                await codeCommand.HandleAsync(context, wrappedServiceProviderFactory, eevoPkcs11ServiceProvider, fileArgument);
            });
        }

        #endregion Methods
    }
}
