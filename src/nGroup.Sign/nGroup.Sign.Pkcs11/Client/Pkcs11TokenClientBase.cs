// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Client
{
  using nGroup.Sign.Pkcs11.Server;
  using System;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;

  internal abstract class Pkcs11TokenClientBase
  {
    #region Properties

    public string? CertificateName { get; protected set; }
    public string? Credential { get; protected set; }
    public Uri? KeyVaultUrl { get; protected set; }
    public IPkcs11TokenAccessApi? TokenAccessApi { get; protected set; }

    #endregion Properties

    #region Methods

    public static void EnsureInitialized(Pkcs11TokenClientBase pkcs11TokenClientBase)
    {
      if (pkcs11TokenClientBase == null)
      {
        throw new ArgumentNullException(nameof(pkcs11TokenClientBase));
      }

      if (pkcs11TokenClientBase.CertificateName == null)
      {
        throw new InvalidOperationException("Not initialized.");
      }

      if (pkcs11TokenClientBase.TokenAccessApi == null)
      {
        throw new InvalidOperationException("Not initialized.");
      }
    }

    public virtual Task<RSA> GetRsaAsync()
    {
      return Task.FromResult<RSA>(new RSAProvider(this));
    }

    public virtual void Initialize(Uri keyVaultUrl, string credential, string certificateName)
    {
      this.KeyVaultUrl = keyVaultUrl;
      this.Credential = credential;
      this.CertificateName = certificateName;
    }

    internal virtual async Task<X509Certificate2> GetCertificateAsync()
    {
      EnsureInitialized(this);
      var certificate = await this.TokenAccessApi!.GetCertificateAsync(this.Credential!, this.CertificateName!);
      return new X509Certificate2(certificate);
    }

    internal virtual async Task<byte[]> SignHashAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      EnsureInitialized(this);
      var signature = await this.TokenAccessApi!.RsaSignHashAsync(this.Credential!, this.CertificateName!, hash, hashAlgorithm, padding);
      return signature;
    }

    internal virtual async Task<bool> VerifyHashAsync(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      EnsureInitialized(this);
      var result = await this.TokenAccessApi!.RsaVerifyHashAsync(this.Credential!, this.CertificateName!, hash, signature, hashAlgorithm, padding);
      return result;
    }

    #endregion Methods
  }
}