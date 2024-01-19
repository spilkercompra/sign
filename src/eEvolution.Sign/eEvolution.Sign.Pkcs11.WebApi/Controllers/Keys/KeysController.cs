// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.WebApi.Controllers.Keys
{
  using Microsoft.AspNetCore.Http.HttpResults;
  using Microsoft.AspNetCore.Mvc;
  using Newtonsoft.Json;
  using eEvolution.Sign.Pkcs11;
  using eEvolution.Sign.Pkcs11.Server;
  using System.ComponentModel.DataAnnotations;

  [ApiController]
  [Route("[controller]")]
  public class KeysController
  {
    #region Fields

    private readonly ILogger<KeysController> logger;
    private readonly IPkcs11TokenAccessApi pkcs11TokenAccessApi;

    #endregion Fields

    #region Constructors

    public KeysController(IPkcs11TokenAccessApi pkcs11TokenAccessApi, ILogger<KeysController> logger)
    {
      this.pkcs11TokenAccessApi = pkcs11TokenAccessApi;
      this.logger = logger;
    }

    #endregion Constructors

    #region Methods

    [HttpGet("{certificateName}")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<Results<Ok<byte[]>, ProblemHttpResult>> Certificate(
      [FromHeader][Required] string credential,
      [FromRoute][Required] string certificateName)
    {
      try
      {
        var result = await pkcs11TokenAccessApi.GetCertificateAsync(
          credential,
          certificateName);
        return TypedResults.Ok(result);
      }
      catch (Exception exc)
      {
        return ToProblemHttpResult(exc);
      }
    }

    [HttpPost("{certificateName}/sign")]
    [ProducesResponseType(typeof(byte[]), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<Results<Ok<byte[]>, ProblemHttpResult>> Sign(
      [FromHeader][Required] string credential,
      [FromRoute][Required] string certificateName,
      [FromBody][Required] SignRequest signRequest)
    {
      try
      {
        var result = await pkcs11TokenAccessApi.RsaSignHashAsync(
          credential,
          certificateName,
          signRequest.hash,
          ConvertUtils.StringToHashAlgorithmName(signRequest.hashAlgorithmName),
          ConvertUtils.RSASignaturePaddingModeToRSASignaturePadding(signRequest.signaturePaddingMode));
        return TypedResults.Ok(result);
      }
      catch (Exception exc)
      {
        return ToProblemHttpResult(exc);
      }
    }

    [HttpGet("")]
    [ProducesResponseType(typeof(IAsyncEnumerable<TokenInfos>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<Results<Ok<IAsyncEnumerable<TokenInfos>>, ProblemHttpResult>> Tokens()
    {
      try
      {
        var result = await pkcs11TokenAccessApi.GetTokenInfosAsync();
        return TypedResults.Ok(ToAsyncEnumerable(result));
      }
      catch (Exception exc)
      {
        return ToProblemHttpResult(exc);
      }
    }

    [HttpPost("{certificateName}/verify")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<Results<Ok<bool>, ProblemHttpResult>> Verify(
          [FromHeader][Required] string credential,
          [FromRoute][Required] string certificateName,
          [FromBody][Required] VerifiyRequest verifyRequest)
    {
      try
      {
        var result = await pkcs11TokenAccessApi.RsaVerifyHashAsync(
          credential,
          certificateName,
          verifyRequest.hash,
          verifyRequest.signature,
          ConvertUtils.StringToHashAlgorithmName(verifyRequest.hashAlgorithmName),
          ConvertUtils.RSASignaturePaddingModeToRSASignaturePadding(verifyRequest.signaturePaddingMode));
        return TypedResults.Ok(result);
      }
      catch (Exception exc)
      {
        return ToProblemHttpResult(exc);
      }
    }

    private static async IAsyncEnumerable<T> ToAsyncEnumerable<T>(IEnumerable<T> input)
    {
      foreach (var item in input)
      {
        await Task.Yield();
        yield return item;
      }
    }

    private static ProblemHttpResult ToProblemHttpResult(Exception exc)
    {
      return TypedResults.Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: exc.Message,
                detail: exc.ToString());
    }

    #endregion Methods
  }
}