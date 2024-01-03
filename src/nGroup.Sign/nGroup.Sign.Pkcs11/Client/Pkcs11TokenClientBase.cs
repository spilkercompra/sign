// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Client
{
  using System;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;

  internal abstract class Pkcs11TokenClientBase
  {
    #region Properties

    public string? CertificateName { get; private set; }
    public string? Credential { get; private set; }
    public Uri? KeyVaultUrl { get; private set; }

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
    }

    public abstract Task<X509Certificate2> GetCertificateAsync();

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

    internal abstract Task<byte[]> SignHashAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding);

    internal abstract Task<bool> VerifyHashAsync(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding);

    #endregion Methods
  }
}