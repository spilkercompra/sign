// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.WebApi
{
  using eEvolution.Sign.Pkcs11;
  using eEvolution.Sign.Pkcs11.Server;
  using System.Net.Http;
  using System.Security.Cryptography;
  using System.Threading.Tasks;

  public partial class RemoteSignClient : IEEvoPkcs11TokenAccessApi, IWebApiClient<RemoteSignClient>
  {
    #region Methods

    public static RemoteSignClient Create(string baseUrl, HttpClient httpClient)
    {
      return new RemoteSignClient(baseUrl, httpClient);
    }

    Task<byte[]> IEEvoPkcs11TokenAccessApi.GetCertificateAsync(string credential, string certificateName)
    {
      return this.GetCertificateAsync(credential, certificateName);
    }

    async Task<Server.TokenInfos[]> IEEvoPkcs11TokenAccessApi.GetTokenInfosAsync()
    {
      var tokenInfos = await this.GetTokenInfosAsync();
      return ConvertUtils.CloneConverted<Server.TokenInfos[]>(tokenInfos);
    }

    Task<byte[]> IEEvoPkcs11TokenAccessApi.RsaSignHashAsync(string credential, string certificateName, byte[] hash, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding)
    {
      return this.RsaSignHashAsync(credential, certificateName, hash, hashAlgorithmName.Name, signaturePadding.Mode.ToString());
    }

    Task<bool> IEEvoPkcs11TokenAccessApi.RsaVerifyHashAsync(string credential, string certificateName, byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding)
    {
      return this.RsaVerifyHashAsync(credential, certificateName, hash, signature, hashAlgorithmName.Name, signaturePadding.Mode.ToString());
    }

    #endregion Methods
  }
}