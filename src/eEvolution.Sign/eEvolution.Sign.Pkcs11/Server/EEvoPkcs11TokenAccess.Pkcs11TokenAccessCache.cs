// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using System.Security.Cryptography.X509Certificates;

  internal static partial class EEvoPkcs11TokenAccess
  {
    #region Classes

    private class Pkcs11TokenAccessCache
    {
      #region Properties

      public Dictionary<string, CertificateReference> Certificates { get; } = new Dictionary<string, CertificateReference>(StringComparer.OrdinalIgnoreCase);
      public Dictionary<string, StoreReference> Stores { get; } = new Dictionary<string, StoreReference>(StringComparer.OrdinalIgnoreCase);
      public Dictionary<string, X509Certificate2> X509Certificates { get; } = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

      #endregion Properties
    }

    #endregion Classes
  }
}