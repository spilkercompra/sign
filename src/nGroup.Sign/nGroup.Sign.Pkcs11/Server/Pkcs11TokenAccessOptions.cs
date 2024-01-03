﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Server
{
  using Microsoft.Extensions.Configuration;

  internal class Pkcs11TokenAccessOptions
  {
    #region Properties

    public Dictionary<string, List<string>> CredentialsAndTokenIds { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> EnvironmentVariables { get; set; } = new Dictionary<string, string>();
    public List<string> Pkcs11LibraryPaths { get; set; } = new List<string>();
    public Dictionary<string, string> TokenIdsAndTokenPins { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    #endregion Properties

    #region Methods

    internal static Pkcs11TokenAccessOptions GetInstance()
    {
      var configurationBuilder = new ConfigurationBuilder();
      var basePath = new FileInfo(typeof(Pkcs11TokenAccessOptions).Assembly.Location).DirectoryName!;

      configurationBuilder
          .SetBasePath(basePath)
          .AddJsonFile("nGroup.Sign.Pkcs11.appsettings.json", optional: false, reloadOnChange: false)
          .AddEnvironmentVariables();

      var configurationRoot = configurationBuilder.Build();
      var section = configurationRoot.GetRequiredSection(nameof(Pkcs11TokenAccessOptions));
      var options = section.Get<Pkcs11TokenAccessOptions>();

      return options!;
    }

    #endregion Methods
  }
}