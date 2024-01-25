// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.WebApi.Controllers.RemoteSign
{
  using Microsoft.AspNetCore.Mvc;
  using eEvolution.Sign.Pkcs11;
  using eEvolution.Sign.Pkcs11.Server;
  using RSASignaturePaddingMode = System.Security.Cryptography.RSASignaturePaddingMode;

  [ApiController]
  [Route("[controller]")]
  public partial class RemoteSignController : ControllerBase
  {
    #region Fields

    private readonly ILogger<RemoteSignController> logger;
    private readonly IEEvoPkcs11TokenAccessApi pkcs11TokenAccessApi;

    #endregion Fields

    #region Constructors

    public RemoteSignController(IEEvoPkcs11TokenAccessApi pkcs11TokenAccessApi, ILogger<RemoteSignController> logger)
    {
      this.pkcs11TokenAccessApi = pkcs11TokenAccessApi;
      this.logger = logger;
    }

    #endregion Constructors

    #region Methods

    [HttpGet("GetCertificate")]
    public async Task<byte[]> GetCertificate(string credential, string certificateName)
    {
      return await pkcs11TokenAccessApi.GetCertificateAsync(credential, certificateName);
    }

    [HttpGet("GetTokenInfos")]
    public async Task<TokenInfos[]> GetTokenInfos()
    {
      return await pkcs11TokenAccessApi.GetTokenInfosAsync();
    }

    [HttpPost("RsaSignHash")]
    public async Task<byte[]> RsaSignHash(
      [FromQuery] string credential,
      [FromQuery] string certificateName,
      [FromForm] byte[] hash,
      [FromForm] string hashAlgorithmName,
      [FromForm] RSASignaturePaddingMode signaturePaddingMode)
    {
      return await pkcs11TokenAccessApi.RsaSignHashAsync(
        credential,
        certificateName,
        hash,
        ConvertUtils.StringToHashAlgorithmName(hashAlgorithmName),
        ConvertUtils.RSASignaturePaddingModeToRSASignaturePadding(signaturePaddingMode));
    }

    [HttpPost("RsaVerifyHash")]
    public async Task<bool> RsaVerifyHash(
      [FromQuery] string credential,
      [FromQuery] string certificateName,
      [FromForm] byte[] hash,
      [FromForm] byte[] signature,
      [FromForm] string hashAlgorithmName,
      [FromForm] RSASignaturePaddingMode signaturePaddingMode)
    {
      return await pkcs11TokenAccessApi.RsaVerifyHashAsync(
        credential,
        certificateName,
        hash,
        signature,
        ConvertUtils.StringToHashAlgorithmName(hashAlgorithmName),
        ConvertUtils.RSASignaturePaddingModeToRSASignaturePadding(signaturePaddingMode));
    }

    #endregion Methods
  }
}