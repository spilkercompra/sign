namespace eEvolution.Sign.Cli
{
  using eEvolution.Sign.Cli.Tools;
  using Microsoft.Extensions.DependencyInjection;

  internal static class IServiceCollectionExtensions
  {
    #region Methods

    public static void ReplaceExact(this IServiceCollection services, ServiceDescriptor toBeReplaced, ServiceDescriptor replacement)
    {
      for (int i = 0; i < services.Count; i++)
      {
        var sd = services[i];
        if (ServiceDescriptorEqualityComparerByServiceTypeAndImplementationType.Default.Equals(sd, toBeReplaced))
        {
          services[i] = replacement;
        }
      }
    }

    #endregion Methods
  }
}