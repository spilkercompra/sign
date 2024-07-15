// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11
{
  using eEvolution.Sign.Pkcs11.Client;
  using eEvolution.Sign.Pkcs11.Server;
  using eEvolution.Sign.Pkcs11.WebApi;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;

  public class EEvoPkcs11Service
  {
    #region Fields

    private readonly EEvoPkcs11TokenClientBase pkcs11TokenClient;

    #endregion Fields

    #region Constructors

    public EEvoPkcs11Service(bool useLocalClient)
    {
      if (useLocalClient)
      {
        this.pkcs11TokenClient = new EEvoPkcs11TokenLocalClient();
      }
      else
      {
        this.pkcs11TokenClient = new EEvoPkcs11TokenRemoteClient<KeysClient>();
      }
    }

    #endregion Constructors

    #region Methods

    public Task<X509Certificate2> GetCertificateAsync()
    {
      return this.pkcs11TokenClient.GetCertificateAsync();
    }

    public Task<RSA> GetRsaAsync()
    {
      return this.pkcs11TokenClient.GetRsaAsync();
    }

    public void Initialize(Uri keyVaultUrl, (string id, string clientId, string clientSecret) credentials, string certificateName)
    {
      var credential = SimpleClientSecret.ToCredential(credentials.id, credentials.clientId, credentials.clientSecret);
      this.pkcs11TokenClient.Initialize(keyVaultUrl, credential, certificateName);
    }

    #endregion Methods
  }
}