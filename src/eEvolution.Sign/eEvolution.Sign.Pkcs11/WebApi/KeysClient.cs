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

  public partial class KeysClient : IPkcs11TokenAccessApi, IWebApiClient<KeysClient>
  {
    #region Methods

    public static KeysClient Create(string baseUrl, HttpClient httpClient)
    {
      return new KeysClient(baseUrl, httpClient);
    }

    async Task<byte[]> IPkcs11TokenAccessApi.GetCertificateAsync(string credential, string certificateName)
    {
      try
      {
        var result = await this.CertificateAsync(credential, certificateName);
        return result;
      }
      catch (ApiException<ProblemDetails> exc)
      {
        var details = exc.Result;
        throw new ApiException(details.Title, exc.StatusCode, details.Detail, exc.Headers, exc);
      }
    }

    async Task<Server.TokenInfos[]> IPkcs11TokenAccessApi.GetTokenInfosAsync()
    {
      try
      {
        var result = await this.TokensAsync();
        return ConvertUtils.CloneConverted<Server.TokenInfos[]>(result);
      }
      catch (ApiException<ProblemDetails> exc)
      {
        var details = exc.Result;
        throw new ApiException(details.Title, exc.StatusCode, details.Detail, exc.Headers, exc);
      }
    }

    async Task<byte[]> IPkcs11TokenAccessApi.RsaSignHashAsync(string credential, string certificateName, byte[] hash, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding)
    {
      try
      {
        var result = await this.SignAsync(
          credential,
          certificateName,
          new SignRequest()
          {
            Hash = hash,
            HashAlgorithmName = hashAlgorithmName.Name,
            SignaturePaddingMode = (RSASignaturePaddingMode)signaturePadding.Mode
          });
        return result;
      }
      catch (ApiException<ProblemDetails> exc)
      {
        var details = exc.Result;
        throw new ApiException(details.Title, exc.StatusCode, details.Detail, exc.Headers, exc);
      }
    }

    async Task<bool> IPkcs11TokenAccessApi.RsaVerifyHashAsync(string credential, string certificateName, byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding signaturePadding)
    {
      try
      {
        var result = await this.VerifyAsync(
          credential,
          certificateName,
          new VerifiyRequest()
          {
            Hash = hash,
            Signature = signature,
            HashAlgorithmName = hashAlgorithmName.Name,
            SignaturePaddingMode = (RSASignaturePaddingMode)signaturePadding.Mode
          });
        return result;
      }
      catch (ApiException<ProblemDetails> exc)
      {
        var details = exc.Result;
        throw new ApiException(details.Title, exc.StatusCode, details.Detail, exc.Headers, exc);
      }
    }

    #endregion Methods
  }
}