// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Client
{
  using eEvolution.Sign.Pkcs11.Server;
  using System;

  internal class EEvoPkcs11TokenLocalClient : EEvoPkcs11TokenClientBase
  {
    #region Methods

    public override void Initialize(Uri keyVaultUrl, string credential, string certificateName)
    {
      base.Initialize(keyVaultUrl, credential, certificateName);
      this.TokenAccessApi = new EEvoPkcs11TokenAccessApi();
    }

    #endregion Methods
  }
}