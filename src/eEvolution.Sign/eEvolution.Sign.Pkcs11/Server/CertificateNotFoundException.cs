// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using System;

  [Serializable]
  public class CertificateNotFoundException : Exception
  {
    #region Constructors

    public CertificateNotFoundException()
    { }

    public CertificateNotFoundException(string message) : base(message)
    {
    }

    public CertificateNotFoundException(string message, Exception inner) : base(message, inner)
    {
    }

    #endregion Constructors
  }
}