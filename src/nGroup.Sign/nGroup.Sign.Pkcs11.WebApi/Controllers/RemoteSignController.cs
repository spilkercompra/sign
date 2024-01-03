// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.WebApi.Controllers
{
  using Microsoft.AspNetCore.Mvc;
  using Newtonsoft.Json;
  using nGroup.Sign.Pkcs11.Server;
  using System.Security.Cryptography;

  [ApiController]
  [Route("[controller]")]
  public class RemoteSignController : ControllerBase
  {
    #region Fields

    private readonly ILogger<RemoteSignController> logger;

    #endregion Fields

    #region Constructors

    public RemoteSignController(ILogger<RemoteSignController> logger)
    {
      this.logger = logger;
    }

    #endregion Constructors

    #region Methods

    [HttpGet("GetCertificate")]
    public byte[] GetCertificate(string credential, string certificateName)
    {
      return Pkcs11TokenAccess.GetCertificate(credential, certificateName);
    }

    [HttpGet("GetTokenInfos")]
    public TokenInfos[] GetTokenInfos()
    {
      return Pkcs11TokenAccess.GetTokenInfos();
    }

    [HttpPost("RsaSignHash")]
    public byte[] RsaSignHash(
      [FromQuery] string credential,
      [FromQuery] string certificateName,
      [FromForm] byte[] hash,
      [FromForm] string hashAlgorithmName,
      [FromForm] RSASignaturePaddingMode signaturePaddingMode)
    {
      return Pkcs11TokenAccess.RsaSignHash(credential, certificateName, hash, hashAlgorithmName, signaturePaddingMode);
    }

    [HttpPost("RsaVerifyHash")]
    public bool RsaVerifyHash(
      [FromQuery] string credential,
      [FromQuery] string certificateName,
      [FromForm] byte[] hash,
      [FromForm] byte[] signature,
      [FromForm] string hashAlgorithmName,
      [FromForm] RSASignaturePaddingMode signaturePaddingMode)
    {
      return Pkcs11TokenAccess.RsaVerifyHash(credential, certificateName, hash, signature, hashAlgorithmName, signaturePaddingMode);
    }

    #endregion Methods
  }
}