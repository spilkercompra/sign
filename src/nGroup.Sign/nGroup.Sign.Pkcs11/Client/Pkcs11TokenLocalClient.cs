// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Client
{
  using nGroup.Sign.Pkcs11.Server;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;

  internal class Pkcs11TokenLocalClient : Pkcs11TokenClientBase
  {
    #region Methods

    public override Task<X509Certificate2> GetCertificateAsync()
    {
      EnsureInitialized(this);
      var certificate = Pkcs11TokenAccess.GetCertificate(this.Credential!, this.CertificateName!);
      return Task.FromResult(new X509Certificate2(certificate));
    }

    internal override Task<byte[]> SignHashAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      EnsureInitialized(this);
      var signature = Pkcs11TokenAccess.RsaSignHash(this.Credential!, this.CertificateName!, hash, hashAlgorithm.Name!, padding.Mode);
      return Task.FromResult(signature);
    }

    internal override Task<bool> VerifyHashAsync(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      EnsureInitialized(this);
      var result = Pkcs11TokenAccess.RsaVerifyHash(this.Credential!, this.CertificateName!, hash, signature, hashAlgorithm.Name!, padding.Mode);
      return Task.FromResult(result);
    }

    #endregion Methods
  }
}