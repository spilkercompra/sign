namespace eEvolution.Sign.Cli
{
  using Microsoft.Extensions.Logging;
  using global::Sign.Core;
  using System;
  using Microsoft.Extensions.DependencyInjection;
  using Microsoft.Extensions.Configuration;
  using Microsoft.Extensions.DependencyInjection.Extensions;

  internal class ServiceProviderFactoryWrapper : IServiceProviderFactory
  {
    #region Constructors

    public ServiceProviderFactoryWrapper(IServiceProviderFactory parent, IServiceCollection serviceCollection)
    {
      this.Parent = parent;
      this.ServiceCollection = serviceCollection;
    }

    #endregion Constructors

    #region Properties

    public IServiceProviderFactory Parent { get; }
    public IServiceCollection ServiceCollection { get; }

    #endregion Properties

    #region Methods

    public IServiceProvider Create(LogLevel logLevel = LogLevel.Information, ILoggerProvider? loggerProvider = null)
    {
      var provider = this.Parent.Create(logLevel, loggerProvider);
      AddDefault(this.ServiceCollection);
      return new ServiceProviderWrapper(provider, this.ServiceCollection);
    }

    internal static void AddDefault(
            IServiceCollection services,
            LogLevel logLevel = LogLevel.Information,
            ILoggerProvider? loggerProvider = null)
    {
      IConfigurationBuilder configurationBuilder = new ConfigurationBuilder();
      AppRootDirectoryLocator locator = new();

      configurationBuilder.SetBasePath(locator.Directory.FullName)
          .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
          .AddEnvironmentVariables();

      IConfiguration configuration = configurationBuilder.Build();
      IConfigurationSection loggingSection = configuration.GetSection("Logging");

      services.AddLogging(builder =>
      {
        builder = builder.SetMinimumLevel(logLevel)
                  .AddConfiguration(loggingSection)
                  .AddConsole();

        if (loggerProvider is not null)
        {
          builder.AddProvider(loggerProvider);
        }
      });

      services.TryAddSingleton<IAppRootDirectoryLocator, AppRootDirectoryLocator>();
      services.TryAddSingleton<IToolConfigurationProvider, ToolConfigurationProvider>();
      services.TryAddSingleton<IMatcherFactory, MatcherFactory>();
      services.TryAddSingleton<IFileListReader, FileListReader>();
      services.TryAddSingleton<IFileMatcher, FileMatcher>();
      services.TryAddSingleton<IContainerProvider, ContainerProvider>();
      services.TryAddSingleton<IFileMetadataService, FileMetadataService>();
      services.TryAddSingleton<IDirectoryService, DirectoryService>();
      services.TryAddSingleton<IKeyVaultService, KeyVaultService>();
      services.TryAddSingleton<ISignatureProvider, AzureSignToolSignatureProvider>();
      services.TryAddSingleton<ISignatureProvider, ClickOnceSignatureProvider>();
      services.TryAddSingleton<ISignatureProvider, VsixSignatureProvider>();
      services.TryAddSingleton<ISignatureProvider, NuGetSignatureProvider>();
      services.TryAddSingleton<ISignatureProvider, AppInstallerServiceSignatureProvider>();
      services.TryAddSingleton<IDefaultSignatureProvider, DefaultSignatureProvider>();
      services.TryAddSingleton<IAggregatingSignatureProvider, AggregatingSignatureProvider>();
      services.TryAddSingleton<IManifestSigner, ManifestSigner>();
      services.TryAddSingleton<IMageCli, MageCli>();
      services.TryAddSingleton<IMakeAppxCli, MakeAppxCli>();
      services.TryAddSingleton<INuGetSignTool, NuGetSignTool>();
      services.TryAddSingleton<IOpenVsixSignTool, OpenVsixSignTool>();
      services.TryAddSingleton<ICertificateVerifier, CertificateVerifier>();
      services.TryAddSingleton<ISigner, Signer>();
    }

    #endregion Methods
  }
}