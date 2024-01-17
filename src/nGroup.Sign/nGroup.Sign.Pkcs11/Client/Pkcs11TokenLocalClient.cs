// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Client
{
  using nGroup.Sign.Pkcs11.Server;
  using System;

  internal class Pkcs11TokenLocalClient : Pkcs11TokenClientBase
  {
    #region Methods

    public override void Initialize(Uri keyVaultUrl, string credential, string certificateName)
    {
      base.Initialize(keyVaultUrl, credential, certificateName);
      this.TokenAccessApi = new Pkcs11TokenAccessApi();
    }

    #endregion Methods
  }
}