// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using System.Security.Cryptography;

  public interface IPkcs11TokenAccessApi
  {
    #region Methods

    Task<byte[]> GetCertificateAsync(string credential, string certificateName);

    Task<TokenInfos[]> GetTokenInfosAsync();

    Task<byte[]> RsaSignHashAsync(string credential, string certificateName, byte[] hash, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding);

    Task<bool> RsaVerifyHashAsync(string credential, string certificateName, byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding);

    #endregion Methods
  }
}