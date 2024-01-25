namespace eEvolution.Sign.Cli.Tools
{
  using Microsoft.Extensions.DependencyInjection;
  using System;

  internal class ServiceProviderWrapper : IServiceProvider
  {
    #region Constructors

    public ServiceProviderWrapper(IServiceProvider parent, IServiceCollection serviceCollection)
    {
      Parent = parent;
      Own = serviceCollection.BuildServiceProvider();
    }

    #endregion Constructors

    #region Properties

    public IServiceProvider Own { get; }
    public IServiceProvider Parent { get; }

    #endregion Properties

    #region Methods

    public object? GetService(Type serviceType)
    {
      var isEnumerable = serviceType.IsGenericType
                         && typeof(IEnumerable<>).IsAssignableFrom(serviceType.GetGenericTypeDefinition());
      if (isEnumerable)
      {
        var enumerableType = serviceType.GenericTypeArguments[0];
        var enumerableResult = Parent.GetServices(enumerableType)
                          .Concat(Own.GetServices(enumerableType))
                          .ToArray();
        return enumerableResult;
      }

      var result = Own.GetService(serviceType) ?? Parent.GetService(serviceType);
      return result;
    }

    #endregion Methods
  }
}