// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.WebApi.Controllers.Keys
{
  using System.Security.Cryptography;

  public record struct SignRequest(byte[] hash, string hashAlgorithmName, RSASignaturePaddingMode signaturePaddingMode)
  {
    public static implicit operator (byte[] hash, string hashAlgorithmName, RSASignaturePaddingMode signaturePaddingMode)(SignRequest value)
    {
      return (value.hash, value.hashAlgorithmName, value.signaturePaddingMode);
    }

    public static implicit operator SignRequest((byte[] hash, string hashAlgorithmName, RSASignaturePaddingMode signaturePaddingMode) value)
    {
      return new SignRequest(value.hash, value.hashAlgorithmName, value.signaturePaddingMode);
    }
  }
}