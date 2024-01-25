namespace eEvolution.Sign.Cli.KeyVault
{
    using Azure.Core;
    using eEvolution.Sign.Pkcs11;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using global::Sign.Core;
    using System.Reflection;
    using Azure.Identity;

    public class EEvoPkcs11KeyVaultServiceAdaptor : IKeyVaultService
    {
        #region Fields

        private readonly EEvoPkcs11KeyVaultService pkcs11KeyVaultService;

        #endregion Fields

        #region Constructors

        public EEvoPkcs11KeyVaultServiceAdaptor(bool useLocalClient)
        {
            pkcs11KeyVaultService = new EEvoPkcs11KeyVaultService(useLocalClient);
        }

        #endregion Constructors

        #region Methods

        public Task<X509Certificate2> GetCertificateAsync()
        {
            return pkcs11KeyVaultService.GetCertificateAsync();
        }

        public Task<RSA> GetRsaAsync()
        {
            return pkcs11KeyVaultService.GetRsaAsync();
        }

        public void Initialize(Uri keyVaultUrl, TokenCredential tokenCredential, string certificateName)
        {
            var clientSecretCredential = (ClientSecretCredential)tokenCredential;

            /////// <summary>
            /////// Gets the Microsoft Entra tenant (directory) Id of the service principal
            /////// </summary>
            ////internal string TenantId { get; }
            var id = getTokenCredentialProperty(clientSecretCredential, "TenantId") ?? string.Empty;

            /////// <summary>
            /////// Gets the client (application) ID of the service principal
            /////// </summary>
            ////internal string ClientId { get; }
            var clientId = getTokenCredentialProperty(clientSecretCredential, "ClientId") ?? string.Empty;

            /////// <summary>
            /////// Gets the client secret that was generated for the App Registration used to authenticate the client.
            /////// </summary>
            ////internal string ClientSecret { get; }
            var clientSecret = getTokenCredentialProperty(clientSecretCredential, "ClientSecret") ?? string.Empty;

            pkcs11KeyVaultService.Initialize(keyVaultUrl, (id, clientId, clientSecret), certificateName);

            static string? getTokenCredentialProperty(ClientSecretCredential tokenCredential, string propertyName)
            {
                return (string?)typeof(ClientSecretCredential)
                                 .GetProperty(propertyName, BindingFlags.Instance | BindingFlags.NonPublic)!
                                 .GetValue(tokenCredential);
            }
        }

        #endregion Methods
    }
}