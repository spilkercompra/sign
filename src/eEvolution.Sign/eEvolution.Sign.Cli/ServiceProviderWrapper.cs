namespace eEvolution.Sign.Cli
{
  using global::Sign.Core;
  using Microsoft.Extensions.DependencyInjection;
  using System;

  internal class ServiceProviderWrapper : IServiceProvider
  {
    #region Constructors

    public ServiceProviderWrapper(IServiceProvider parent, IServiceCollection serviceCollection)
    {
      this.Parent = parent;
      this.Own = serviceCollection.BuildServiceProvider();
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
        var enumerableResult = this.Parent.GetServices(enumerableType)
                          .Concat(this.Own.GetServices(enumerableType))
                          .ToArray();
        return enumerableResult;
      }

      var result = this.Own.GetService(serviceType) ?? this.Parent.GetService(serviceType);
      return result;
    }

    #endregion Methods
  }
}