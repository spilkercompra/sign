namespace eEvolution.Sign.Cli.Tools
{
  using Microsoft.Extensions.Logging;
  using global::Sign.Core;
  using System;
  using Microsoft.Extensions.DependencyInjection;

  internal class ServiceProviderFactoryWrapper : IServiceProviderFactory
  {
    #region Constructors

    public ServiceProviderFactoryWrapper(IServiceProviderFactory parent)
    {
      this.Parent = parent;
    }

    #endregion Constructors

    #region Properties

    private IServiceProviderFactory Parent { get; }
    public Action<IServiceCollection>? AfterAddServices { get; set; }

    #endregion Properties

    #region Methods

    public IServiceProvider Create(LogLevel logLevel = LogLevel.Information, ILoggerProvider? loggerProvider = null, Action<IServiceCollection>? addServices = null)
    {
      var combinedAddServices = new Action<IServiceCollection>(serviceCollection =>
      {
          addServices?.Invoke(serviceCollection);
          this.AfterAddServices?.Invoke(serviceCollection);
      });
      return this.Parent.Create(logLevel, loggerProvider, combinedAddServices);
    }

    #endregion Methods
  }
}
