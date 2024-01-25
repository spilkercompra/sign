namespace eEvolution.Sign.Cli.Tools
{
  using Microsoft.Extensions.Logging;
  using global::Sign.Core;
  using System;
  using Microsoft.Extensions.DependencyInjection;
  using Microsoft.Extensions.Configuration;

  internal class ServiceProviderFactoryWrapper : IServiceProviderFactory
  {
    #region Fields

    public event EventHandler<(IServiceProvider parentProvider, IServiceCollection servicesWithDefaults)>? Configure;

    #endregion Fields

    #region Constructors

    public ServiceProviderFactoryWrapper(IServiceProviderFactory parent)
    {
      Parent = parent;
      ServiceCollection = new ServiceCollection();
    }

    #endregion Constructors

    #region Properties

    public IServiceProviderFactory Parent { get; }
    public IServiceCollection ServiceCollection { get; }

    #endregion Properties

    #region Methods

    public IServiceProvider Create(LogLevel logLevel = LogLevel.Information, ILoggerProvider? loggerProvider = null)
    {
      var parentProvider = Parent.Create(logLevel, loggerProvider);
      AddDefault(this.ServiceCollection, logLevel, loggerProvider);
      this.Configure?.Invoke(this, (parentProvider, this.ServiceCollection));
      return new ServiceProviderWrapper(parentProvider, this.ServiceCollection);
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

      services.AddSingleton<IAppRootDirectoryLocator, AppRootDirectoryLocator>();
      services.AddSingleton<IToolConfigurationProvider, ToolConfigurationProvider>();
      services.AddSingleton<IMatcherFactory, MatcherFactory>();
      services.AddSingleton<IFileListReader, FileListReader>();
      services.AddSingleton<IFileMatcher, FileMatcher>();
      services.AddSingleton<IContainerProvider, ContainerProvider>();
      services.AddSingleton<IFileMetadataService, FileMetadataService>();
      services.AddSingleton<IDirectoryService, DirectoryService>();
      services.AddSingleton<IKeyVaultService, KeyVaultService>();
      services.AddSingleton<ISignatureProvider, AzureSignToolSignatureProvider>();
      services.AddSingleton<ISignatureProvider, ClickOnceSignatureProvider>();
      services.AddSingleton<ISignatureProvider, VsixSignatureProvider>();
      services.AddSingleton<ISignatureProvider, NuGetSignatureProvider>();
      services.AddSingleton<ISignatureProvider, AppInstallerServiceSignatureProvider>();
      services.AddSingleton<IDefaultSignatureProvider, DefaultSignatureProvider>();
      services.AddSingleton<IAggregatingSignatureProvider, AggregatingSignatureProvider>();
      services.AddSingleton<IManifestSigner, ManifestSigner>();
      services.AddSingleton<IMageCli, MageCli>();
      services.AddSingleton<IMakeAppxCli, MakeAppxCli>();
      services.AddSingleton<INuGetSignTool, NuGetSignTool>();
      services.AddSingleton<IOpenVsixSignTool, OpenVsixSignTool>();
      services.AddSingleton<ICertificateVerifier, CertificateVerifier>();
      services.AddSingleton<ISigner, Signer>();
    }

    #endregion Methods
  }
}