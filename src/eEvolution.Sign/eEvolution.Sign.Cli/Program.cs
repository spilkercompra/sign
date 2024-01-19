namespace eEvolution.Sign.Cli
{
  using global::Sign.Cli;
  using global::Sign.Core;
  using System.CommandLine.Builder;
  using System.CommandLine.Parsing;

  internal static class Program
  {
    internal static async Task<int> Main(string[] args)
    {
      global::Sign.Cli.Program.ParserFactory = CreateParser;
      return await global::Sign.Cli.Program.Main(args);
    }

    internal static Parser CreateParser(IServiceProviderFactory? serviceProviderFactory = null)
    {
      SignCommand command = new(serviceProviderFactory);

      var codeCommand = command.OfType<CodeCommand>().First();
      codeCommand.AddCommand(new Pkcs11TokenRemoteCommand(codeCommand, serviceProviderFactory ?? new ServiceProviderFactory()));
      codeCommand.AddCommand(new Pkcs11TokenLocalCommand(codeCommand, serviceProviderFactory ?? new ServiceProviderFactory()));

      return new CommandLineBuilder(command)
          .UseVersionOption()
          .UseParseErrorReporting()
          .UseHelp()
          .Build();
    }
  }
}