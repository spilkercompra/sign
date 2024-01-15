// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11
{
  using nGroup.Sign.Pkcs11.Client;
  using nGroup.Sign.Pkcs11.Server;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;

  public class Pkcs11KeyVaultService
  {
    #region Fields

    private readonly Pkcs11TokenClientBase pkcs11TokenClient;

    #endregion Fields

    #region Constructors

    public Pkcs11KeyVaultService(bool useLocalClient)
    {
      if (useLocalClient)
      {
        this.pkcs11TokenClient = new Pkcs11TokenLocalClient();
      }
      else
      {
        this.pkcs11TokenClient = new Pkcs11TokenRemoteClient();
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