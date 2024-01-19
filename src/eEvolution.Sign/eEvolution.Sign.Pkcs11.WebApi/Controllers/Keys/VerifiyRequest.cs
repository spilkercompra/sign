// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.WebApi.Controllers.Keys
{
  using System.Security.Cryptography;

  public record struct VerifiyRequest(byte[] hash, byte[] signature, string hashAlgorithmName, RSASignaturePaddingMode signaturePaddingMode)
  {
    public static implicit operator (byte[] hash, byte[] signature, string hashAlgorithmName, RSASignaturePaddingMode signaturePaddingMode)(VerifiyRequest value)
    {
      return (value.hash, value.signature, value.hashAlgorithmName, value.signaturePaddingMode);
    }

    public static implicit operator VerifiyRequest((byte[] hash, byte[] signature, string hashAlgorithmName, RSASignaturePaddingMode signaturePaddingMode) value)
    {
      return new VerifiyRequest(value.hash, value.signature, value.hashAlgorithmName, value.signaturePaddingMode);
    }
  }
}