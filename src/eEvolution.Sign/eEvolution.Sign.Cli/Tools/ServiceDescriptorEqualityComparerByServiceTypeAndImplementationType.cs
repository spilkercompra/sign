namespace eEvolution.Sign.Cli.Tools
{
  using System;
  using Microsoft.Extensions.DependencyInjection;
  using System.Diagnostics.CodeAnalysis;

  internal class ServiceDescriptorEqualityComparerByServiceTypeAndImplementationType : EqualityComparer<ServiceDescriptor>
  {
    #region Fields

    public new static ServiceDescriptorEqualityComparerByServiceTypeAndImplementationType Default = new ServiceDescriptorEqualityComparerByServiceTypeAndImplementationType();

    #endregion Fields

    #region Methods

    public override bool Equals(ServiceDescriptor? x, ServiceDescriptor? y)
    {
      if (x == null)
      {
        return false;
      }

      if (y == null)
      {
        return false;
      }

      return x.ServiceType == y.ServiceType
          && GetImplementationType(x) == GetImplementationType(y)
          && x.Lifetime == y.Lifetime
          && x.ServiceKey == y.ServiceKey;
    }

    public override int GetHashCode([DisallowNull] ServiceDescriptor obj)
    {
      return HashCode.Combine(obj.ServiceType, GetImplementationType(obj), obj.Lifetime, obj.ServiceKey);
    }

    private static Type GetImplementationType(ServiceDescriptor obj)
    {
      return (obj.ImplementationType ?? obj.ImplementationInstance?.GetType() ?? obj.ImplementationFactory?.Method.ReturnType)!;
    }

    #endregion Methods
  }
}