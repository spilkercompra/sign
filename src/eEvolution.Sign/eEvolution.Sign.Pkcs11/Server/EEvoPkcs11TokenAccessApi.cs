// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using System.Security.Cryptography;

  public class EEvoPkcs11TokenAccessApi : IEEvoPkcs11TokenAccessApi
  {
    #region Methods

    public Task<byte[]> GetCertificateAsync(string credential, string certificateName)
    {
      var certificate = EEvoPkcs11TokenAccess.GetCertificate(credential, certificateName);
      return Task.FromResult(certificate);
    }

    public Task<TokenInfos[]> GetTokenInfosAsync()
    {
      var tokenInfos = EEvoPkcs11TokenAccess.GetTokenInfos();
      return Task.FromResult(tokenInfos);
    }

    public Task<byte[]> RsaSignHashAsync(string credential, string certificateName, byte[] hash, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding)
    {
      var signature = EEvoPkcs11TokenAccess.RsaSignHash(credential, certificateName, hash, hashAlgorithmName, signaturePadding);
      return Task.FromResult(signature);
    }

    public Task<bool> RsaVerifyHashAsync(string credential, string certificateName, byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding)
    {
      var result = EEvoPkcs11TokenAccess.RsaVerifyHash(credential, certificateName, hash, signature, hashAlgorithmName, signaturePadding);
      return Task.FromResult(result);
    }

    #endregion Methods
  }
}