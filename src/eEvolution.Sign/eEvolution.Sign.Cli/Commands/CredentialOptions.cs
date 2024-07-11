namespace eEvolution.Sign.Cli.Commands
{
    using global::Sign.Cli;
    using System.CommandLine;

    internal class CredentialOptions
    {
        #region Properties

        internal Option<string?> ClientIdOption { get; } = new(["--eevo-key-vault-client-id", "-kvi"], Resources.ClientIdOptionDescription);
        internal Option<string?> ClientSecretOption { get; } = new(["--eevo-key-vault-client-secret", "-kvs"], Resources.ClientSecretOptionDescription);
        internal Option<string?> TenantIdOption { get; } = new(["--eevo-key-vault-tenant-id", "-kvt"], Resources.TenantIdOptionDescription);

        #endregion Properties
    }
}
