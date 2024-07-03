namespace eEvolution.Sign.Cli.Commands
{
    using System.CommandLine;
    using global::Sign.Core;
    using global::Sign.Cli;
    using System;
    using Microsoft.Extensions.DependencyInjection;
    using eEvolution.Sign.Cli.Tools;
    using eEvolution.Sign.Cli.DataFormatSigners;
    using eEvolution.Sign.Cli.KeyVault;
    using Microsoft.Extensions.DependencyInjection.Extensions;

    internal static class EEvoPkcs11TokenCommandHandler
    {
        internal static void SetupEEvoPkcs11TokenCommand(Command eevoPkcs11TokenCommand, CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory, EEvoPkcs11TokenCommandHandlerOptions options)
        {
            ArgumentNullException.ThrowIfNull(codeCommand, nameof(codeCommand));
            ArgumentNullException.ThrowIfNull(serviceProviderFactory, nameof(serviceProviderFactory));

            var wrappedServiceProviderFactory = new ServiceProviderFactoryWrapper(serviceProviderFactory);
            var azureKeyVaultCommand = new AzureKeyVaultCommand(codeCommand, wrappedServiceProviderFactory);

            azureKeyVaultCommand.UrlOption.IsRequired = true;
            azureKeyVaultCommand.CertificateOption.IsRequired = true;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteTenantIdOption.IsRequired = true;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientIdOption.IsRequired = true;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientSecretOption.IsRequired = true;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteTenantIdOption.IsHidden = false;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientIdOption.IsHidden = false;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientSecretOption.IsHidden = false;
            azureKeyVaultCommand.AzureCredentialOptions.ObsoleteManagedIdentityOption.IsHidden = true;

            eevoPkcs11TokenCommand.AddOption(azureKeyVaultCommand.UrlOption);
            eevoPkcs11TokenCommand.AddOption(azureKeyVaultCommand.CertificateOption);
            eevoPkcs11TokenCommand.AddOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteTenantIdOption);
            eevoPkcs11TokenCommand.AddOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientIdOption);
            eevoPkcs11TokenCommand.AddOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientSecretOption);
            eevoPkcs11TokenCommand.AddOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteManagedIdentityOption);

            eevoPkcs11TokenCommand.AddArgument(azureKeyVaultCommand.FileArgument);

            eevoPkcs11TokenCommand.SetHandler(async (context) =>
            {
                var url = context.ParseResult.GetValueForOption(azureKeyVaultCommand.UrlOption);
                var tenantId = context.ParseResult.GetValueForOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteTenantIdOption);
                var clientId = context.ParseResult.GetValueForOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientIdOption);
                var secret = context.ParseResult.GetValueForOption(azureKeyVaultCommand.AzureCredentialOptions.ObsoleteClientSecretOption);
                var certificateId = context.ParseResult.GetValueForOption(azureKeyVaultCommand.CertificateOption);

                wrappedServiceProviderFactory.ReplaceParentAddServices = (IServiceCollection services) =>
                  {
                      // ISignatureAlgorithmProvider und ICertificateProvider müssen statt AzureKeyVaultCommand durch unsere Implementierung ersetzt werden.
                      var keyVaultServiceAdaptor = new EEvoPkcs11KeyVaultServiceAdaptor(
                          useLocalClient: options.UseLocalClient,
                          keyVaultUrl: url!,
                          tokenCredential: (tenantId!, clientId!, secret!),
                          certificateId!);

                      services.AddSingleton<ISignatureAlgorithmProvider>(keyVaultServiceAdaptor);
                      services.AddSingleton<ICertificateProvider>(keyVaultServiceAdaptor);

                      // Jsign statt AzureSignToolSignatureProvider
                      // TODO: konfigurierbar machen und ggf. mit neuem Aggregator nur die nicht unterstützten Dateitypen austauschen.
                      // Vorteile derzeit: Läuft auf unserem Buildserver unter unter Windows 8, unterstützt das Append von Signaturen oder skippen von bereits signierten Files.
                      if (options.UseJSign)
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

                await azureKeyVaultCommand.Handler!.InvokeAsync(context);
            });
        }
    }
}
