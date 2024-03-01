namespace eEvolution.Sign.Cli.KeyVault
{
  using Azure.Core;
  using eEvolution.Sign.Pkcs11;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;
  using global::Sign.Core;
  using System.Threading;

  public class EEvoPkcs11KeyVaultServiceAdaptor : ISignatureAlgorithmProvider, ICertificateProvider
  {
    #region Fields

    private readonly EEvoPkcs11KeyVaultService pkcs11KeyVaultService;

    #endregion Fields

    #region Constructors

    public EEvoPkcs11KeyVaultServiceAdaptor(
      bool useLocalClient,
      Uri keyVaultUrl, 
      (string id, string clientId, string clientSecret) tokenCredential, 
      string certificateName)
    {
      pkcs11KeyVaultService = new EEvoPkcs11KeyVaultService(useLocalClient);
      this.Initialize(keyVaultUrl, tokenCredential, certificateName);
    }

    #endregion Constructors

    #region Methods

    public Task<X509Certificate2> GetCertificateAsync(CancellationToken cancellationToken = default)
    {
      return pkcs11KeyVaultService.GetCertificateAsync().WaitAsync(cancellationToken);
    }

    public Task<RSA> GetRsaAsync(CancellationToken cancellationToken = default)
    {
      return pkcs11KeyVaultService.GetRsaAsync().WaitAsync(cancellationToken);
    }

    private void Initialize(
      Uri keyVaultUrl, 
      (string id, string clientId, string clientSecret) tokenCredential, 
      string certificateName)
    {
      this.pkcs11KeyVaultService.Initialize(keyVaultUrl, tokenCredential, certificateName);
    }

    #endregion Methods
  }
}