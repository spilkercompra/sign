namespace eEvolution.Sign.Cli.Commands
{
  using System.CommandLine;
  using global::Sign.Core;
  using global::Sign.Cli;

  internal sealed class EEvoPkcs11TokenLocalCommand : Command
  {
    // ".\eEvolution.Sign.exe" code eevo-pkcs11-token-local *.dll -kvc 9505299957EED70137B0CD033DDB3F2AA027A6DB -d "eEvolution GmbH & Co. KG" -u http://eEvolution.de -kvu https://localhost:7036 -kvt spilker -kvi eEvolution.Sign -kvs Ts52Xavc8hM -o signed\"
    ////internal Option<string> CertificateOption { get; } = new(new[] { "-kvc", "--azure-key-vault-certificate" }, AzureKeyVaultResources.CertificateOptionDescription);
    ////internal Option<string?> ClientIdOption { get; } = new(new[] { "-kvi", "--azure-key-vault-client-id" }, AzureKeyVaultResources.ClientIdOptionDescription);
    ////internal Option<string?> ClientSecretOption { get; } = new(new[] { "-kvs", "--azure-key-vault-client-secret" }, AzureKeyVaultResources.ClientSecretOptionDescription);
    ////internal Argument<string?> FileArgument { get; } = new("file(s)", AzureKeyVaultResources.FilesArgumentDescription);
    ////internal Option<bool> ManagedIdentityOption { get; } = new(new[] { "-kvm", "--azure-key-vault-managed-identity" }, getDefaultValue: () => false, AzureKeyVaultResources.ManagedIdentityOptionDescription);
    ////internal Option<string?> TenantIdOption { get; } = new(new[] { "-kvt", "--azure-key-vault-tenant-id" }, AzureKeyVaultResources.TenantIdOptionDescription);
    ////internal Option<Uri> UrlOption { get; } = new(new[] { "-kvu", "--azure-key-vault-url" }, AzureKeyVaultResources.UrlOptionDescription);

    #region Constructors

    internal EEvoPkcs11TokenLocalCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
        : base("eevo-pkcs11-token-local", "Verwenden Sie EEvo-Pkcs11-Token-Local")
    {
      EEvoPkcs11TokenCommandHandler.SetupEEvoPkcs11TokenCommand(
        this, 
        codeCommand, 
        serviceProviderFactory,
        new EEvoPkcs11TokenCommandHandlerOptions()
        {
          UseLocalClient = true,
          UseJSign = true
        });
    }

    #endregion Constructors
  }
}