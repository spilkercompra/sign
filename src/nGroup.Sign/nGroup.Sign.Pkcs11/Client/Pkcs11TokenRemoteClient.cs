// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Client
{
  using nGroup.Sign.Pkcs11.WebApi;
  using System;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;

  internal class Pkcs11TokenRemoteClient : Pkcs11TokenClientBase
  {
    #region Constructors

    static Pkcs11TokenRemoteClient()
    {
      var handler = new SocketsHttpHandler
      {
        PooledConnectionLifetime = TimeSpan.FromMinutes(15) // Recreate every 15 minutes
      };
      SharedClient = new HttpClient(handler);
    }

    #endregion Constructors

    #region Properties

    public WebApiClient? WebApiClient { get; private set; }
    private static HttpClient SharedClient { get; }

    #endregion Properties

    #region Methods

    public override async Task<X509Certificate2> GetCertificateAsync()
    {
      EnsureInitialized(this);
      var certificate = await this.WebApiClient!.GetCertificateAsync(this.Credential, this.CertificateName);
      return new X509Certificate2(certificate);
    }

    public override void Initialize(Uri keyVaultUrl, string credential, string certificateName)
    {
      base.Initialize(keyVaultUrl, credential, certificateName);
      this.WebApiClient = new WebApiClient(keyVaultUrl.ToString(), SharedClient);
    }

    internal override async Task<byte[]> SignHashAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      EnsureInitialized(this);
      var signature = await this.WebApiClient!.RsaSignHashAsync(this.Credential, this.CertificateName, hash, hashAlgorithm.Name, (WebApi.RSASignaturePaddingMode)padding.Mode);
      return signature;
    }

    internal override async Task<bool> VerifyHashAsync(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      EnsureInitialized(this);
      var result = await this.WebApiClient!.RsaVerifyHashAsync(this.Credential, this.CertificateName, hash, signature, hashAlgorithm.Name, (WebApi.RSASignaturePaddingMode)padding.Mode);
      return result;
    }

    #endregion Methods
  }
}