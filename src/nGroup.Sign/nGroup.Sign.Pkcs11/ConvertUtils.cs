// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11
{
  using System.Security.Cryptography;
  using System.Text.Json;
  using Pkcs11InteropConvertUtils = Net.Pkcs11Interop.Common.ConvertUtils;

  public static class ConvertUtils
  {
    #region Methods

    public static RSASignaturePadding RSASignaturePaddingModeToRSASignaturePadding(RSASignaturePaddingMode signaturePaddingMode) => signaturePaddingMode switch
    {
      RSASignaturePaddingMode.Pkcs1 => RSASignaturePadding.Pkcs1,
      RSASignaturePaddingMode.Pss => RSASignaturePadding.Pss,
      _ => throw new ArgumentException($"Invalid RSASignaturePadding: {signaturePaddingMode}", nameof(signaturePaddingMode))
    };

    public static HashAlgorithmName StringToHashAlgorithmName(string hashAlgorithmName) => hashAlgorithmName switch
    {
      nameof(HashAlgorithmName.MD5) => HashAlgorithmName.MD5,
      nameof(HashAlgorithmName.SHA1) => HashAlgorithmName.SHA1,
      nameof(HashAlgorithmName.SHA256) => HashAlgorithmName.SHA256,
      nameof(HashAlgorithmName.SHA384) => HashAlgorithmName.SHA384,
      nameof(HashAlgorithmName.SHA512) => HashAlgorithmName.SHA512,
      _ => throw new ArgumentException($"Invalid HashAlgorithmName: {hashAlgorithmName}", nameof(hashAlgorithmName))
    };

    internal static string BytesToUtf8String(byte[] tokenPin)
    {
      return Pkcs11InteropConvertUtils.BytesToUtf8String(tokenPin);
    }

    internal static TOut CloneConverted<TOut>(object input)
    {
      var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
      var serializedInput = JsonSerializer.Serialize(input, options);
      var clonedOutput = JsonSerializer.Deserialize<TOut>(serializedInput, options)!;
      return clonedOutput;
    }

    internal static byte[] Utf8StringToBytes(string value)
    {
      return Pkcs11InteropConvertUtils.Utf8StringToBytes(value);
    }

    #endregion Methods
  }
}