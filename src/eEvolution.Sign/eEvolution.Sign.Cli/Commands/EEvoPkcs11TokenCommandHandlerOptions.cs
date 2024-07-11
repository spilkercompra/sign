namespace eEvolution.Sign.Cli.Commands
{
    using global::Sign.Cli;
    using System.CommandLine;

    internal class EEvoPkcs11TokenCommandHandlerOptions
    {
        #region Properties

        internal Option<string> CertificateOption { get; } = new(["--eevo-key-vault-certificate", "-kvc"], AzureKeyVaultResources.CertificateOptionDescription);
        internal CredentialOptions CredentialOptions { get; } = new CredentialOptions();
        internal Argument<string?> FileArgument { get; } = new("file(s)", Resources.FilesArgumentDescription);
        internal Option<Uri> UrlOption { get; } = new(["--eevo-key-vault-url", "-kvu"], AzureKeyVaultResources.UrlOptionDescription);
        internal Option<bool?> UseJSignOption { get; } = new(["--useJSign"], "Use JSign");
        internal bool UseLocalClient { get; set; }

        #endregion Properties
    }
}
