namespace eEvolution.Sign.Cli
{
  using System.CommandLine;
  using System.CommandLine.Invocation;
  using global::Sign.Core;
  using global::Sign.Cli;
  using System;
  using Microsoft.Extensions.DependencyInjection;

  internal sealed class Pkcs11TokenRemoteCommand : Command
  {
    #region Fields

    private readonly AzureKeyVaultCommand _azureKeyVaultCommand;
    private readonly CodeCommand _codeCommand;

    #endregion Fields

    // ".\eEvolution.Sign.exe" code pkcs11-token-remote *.dll -kvc 9505299957EED70137B0CD033DDB3F2AA027A6DB -d "eEvolution GmbH & Co. KG" -u http://eEvolution.de -kvu https://localhost:7036 -kvt spilker -kvi eEvolution.Sign -kvs Ts52Xavc8hM -o signed\"
    ////internal Option<string> CertificateOption { get; } = new(new[] { "-kvc", "--azure-key-vault-certificate" }, AzureKeyVaultResources.CertificateOptionDescription);
    ////internal Option<string?> ClientIdOption { get; } = new(new[] { "-kvi", "--azure-key-vault-client-id" }, AzureKeyVaultResources.ClientIdOptionDescription);
    ////internal Option<string?> ClientSecretOption { get; } = new(new[] { "-kvs", "--azure-key-vault-client-secret" }, AzureKeyVaultResources.ClientSecretOptionDescription);
    ////internal Argument<string?> FileArgument { get; } = new("file(s)", AzureKeyVaultResources.FilesArgumentDescription);
    ////internal Option<bool> ManagedIdentityOption { get; } = new(new[] { "-kvm", "--azure-key-vault-managed-identity" }, getDefaultValue: () => false, AzureKeyVaultResources.ManagedIdentityOptionDescription);
    ////internal Option<string?> TenantIdOption { get; } = new(new[] { "-kvt", "--azure-key-vault-tenant-id" }, AzureKeyVaultResources.TenantIdOptionDescription);
    ////internal Option<Uri> UrlOption { get; } = new(new[] { "-kvu", "--azure-key-vault-url" }, AzureKeyVaultResources.UrlOptionDescription);

    #region Constructors

    internal Pkcs11TokenRemoteCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
        : base("pkcs11-token-remote", "Verwenden Sie Pkcs11-Token-Remote")
    {
      ArgumentNullException.ThrowIfNull(codeCommand, nameof(codeCommand));
      ArgumentNullException.ThrowIfNull(serviceProviderFactory, nameof(serviceProviderFactory));

      // Der IKeyVaultService für das AzureKeyVaultCommand muss durch unsere Implementierung überschrieben werden.
      var services = new ServiceCollection();
      services.AddSingleton<IKeyVaultService>(new Pkcs11KeyVaultServiceWrapper(useLocalClient: false));
      var wrappedServiceProviderFactory = new ServiceProviderFactoryWrapper(serviceProviderFactory, services);

      _codeCommand = codeCommand;
      _azureKeyVaultCommand = new AzureKeyVaultCommand(codeCommand, wrappedServiceProviderFactory);

      AddOption(_azureKeyVaultCommand.UrlOption);
      AddOption(_azureKeyVaultCommand.TenantIdOption);
      AddOption(_azureKeyVaultCommand.ClientIdOption);
      AddOption(_azureKeyVaultCommand.ClientSecretOption);
      AddOption(_azureKeyVaultCommand.CertificateOption);
      AddOption(_azureKeyVaultCommand.ManagedIdentityOption);

      AddArgument(_azureKeyVaultCommand.FileArgument);

      this.SetHandler(async (InvocationContext context) =>
      {
        await _azureKeyVaultCommand.Handler!.InvokeAsync(context);
      });
    }

    #endregion Constructors

  }
}