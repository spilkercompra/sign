namespace eEvolution.Sign.Cli.SignatureProviders
{
    using global::Sign.Core;
    using System;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    internal class EEvoPkcs11ServiceProvider : ISignatureProvider
    {
        #region Fields

        private readonly string certificateName;
        private readonly Uri keyVaultUrl;
        private readonly object lockObject = new();
        private readonly (string id, string clientId, string clientSecret) tokenCredential;
        private readonly bool useLocalClient;
        private EEvoPkcs11ServiceAdaptor? eevoPkcs11ServiceAdaptor;

        #endregion Fields

        #region Constructors

        public EEvoPkcs11ServiceProvider(
          bool useLocalClient,
          Uri keyVaultUrl,
          (string id, string clientId, string clientSecret) tokenCredential,
          string certificateName)
        {
            this.useLocalClient = useLocalClient;
            this.keyVaultUrl = keyVaultUrl;
            this.tokenCredential = tokenCredential;
            this.certificateName = certificateName;
        }

        #endregion Constructors

        #region Methods

        public ICertificateProvider GetCertificateProvider(IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(serviceProvider, nameof(serviceProvider));

            return GetService(serviceProvider);
        }

        public ISignatureAlgorithmProvider GetSignatureAlgorithmProvider(IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(serviceProvider, nameof(serviceProvider));

            return GetService(serviceProvider);
        }

        private EEvoPkcs11ServiceAdaptor GetService(IServiceProvider serviceProvider)
        {
            if (this.eevoPkcs11ServiceAdaptor is not null)
            {
                return this.eevoPkcs11ServiceAdaptor;
            }

            lock (this.lockObject)
            {
                if (this.eevoPkcs11ServiceAdaptor is not null)
                {
                    return this.eevoPkcs11ServiceAdaptor;
                }

                ILogger<EEvoPkcs11ServiceAdaptor> logger = serviceProvider.GetRequiredService<ILogger<EEvoPkcs11ServiceAdaptor>>();
                this.eevoPkcs11ServiceAdaptor = new EEvoPkcs11ServiceAdaptor(
                    this.useLocalClient,
                    this.keyVaultUrl,
                    this.tokenCredential,
                    this.certificateName,
                    logger);
            }

            return this.eevoPkcs11ServiceAdaptor;
        }

        #endregion Methods
    }
}
