namespace eEvolution.Sign.Cli.SignatureProviders
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using global::Sign.Core;
    using System.Threading;
    using System;
    using eEvolution.Sign.Pkcs11;
    using Microsoft.Extensions.Logging;

    internal class EEvoPkcs11ServiceAdaptor : ICertificateProvider, ISignatureAlgorithmProvider
    {
        #region Fields

        private readonly ILogger<EEvoPkcs11ServiceAdaptor> logger;

        private EEvoPkcs11Service eevoPkcs11Service;

        #endregion Fields

        #region Constructors

        public EEvoPkcs11ServiceAdaptor(
         bool useLocalClient,
         Uri keyVaultUrl,
         (string id, string clientId, string clientSecret) tokenCredential,
         string certificateName,
         ILogger<EEvoPkcs11ServiceAdaptor> logger)
        {
            this.eevoPkcs11Service = new EEvoPkcs11Service(useLocalClient);
            this.Initialize(keyVaultUrl, tokenCredential, certificateName);
            this.logger = logger;
        }

        #endregion Constructors

        #region Methods

        public Task<X509Certificate2> GetCertificateAsync(CancellationToken cancellationToken)
        {
            return eevoPkcs11Service.GetCertificateAsync().WaitAsync(cancellationToken);
        }

        public Task<RSA> GetRsaAsync(CancellationToken cancellationToken)
        {
            return eevoPkcs11Service.GetRsaAsync().WaitAsync(cancellationToken);
        }

        private void Initialize(
          Uri keyVaultUrl,
          (string id, string clientId, string clientSecret) tokenCredential,
          string certificateName)
        {
            this.eevoPkcs11Service.Initialize(keyVaultUrl, tokenCredential, certificateName);
        }

        #endregion Methods
    }
}
