// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Client
{
  using System;
  using System.Security.Cryptography;
 
  internal class RSAProvider : RSA
  {
    #region Constructors

    public RSAProvider(Pkcs11TokenClientBase pkcs11TokenClientBase)
    {
      this.Pkcs11TokenClientBase = pkcs11TokenClientBase;
    }

    #endregion Constructors

    #region Properties

    private Pkcs11TokenClientBase Pkcs11TokenClientBase { get; }

    #endregion Properties

    #region Methods

    /// <summary>
    /// Exports the parameters (key) for RSA algorithm
    /// </summary>
    /// <param name="includePrivateParameters">Flag indicating whether to include private parameters</param>
    /// <returns>The parameters (key) for RSA algorithm</returns>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
      if (includePrivateParameters)
      {
        throw new NotSupportedException("Private key export is not supported");
      }

      throw new NotSupportedException("Key export is not supported");
    }

    /// <summary>
    /// Imports the parameters (key) for RSA algorithm
    /// </summary>
    /// <param name="parameters">The parameters (key) for RSA algorithm</param>
    public override void ImportParameters(RSAParameters parameters)
    {
      throw new NotSupportedException("Key import is not supported");
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      if (hash == null || hash.Length == 0)
      {
        throw new ArgumentNullException("hash");
      }

      if (padding == null)
      {
        throw new ArgumentNullException("padding");
      }

      if (padding != RSASignaturePadding.Pkcs1 && padding != RSASignaturePadding.Pss)
      {
        throw new NotSupportedException($"Padding {padding} is not supported");
      }

      return Task.Run(() => this.Pkcs11TokenClientBase.SignHashAsync(hash, hashAlgorithm, padding)).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Verifies that a digital signature is valid by determining the hash value in the signature using the specified hash algorithm and padding, and comparing it to the provided hash value
    /// </summary>
    /// <param name="hash">he hash value of the signed data</param>
    /// <param name="signature">The signature data to be verified</param>
    /// <param name="hashAlgorithm">The hash algorithm used to create the hash value</param>
    /// <param name="padding">The padding mode</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
      if (hash == null || hash.Length == 0)
      {
        throw new ArgumentNullException("hash");
      }

      if (signature == null || signature.Length == 0)
      {
        throw new ArgumentNullException("signature");
      }

      if (padding == null)
      {
        throw new ArgumentNullException("padding");
      }

      if (padding != RSASignaturePadding.Pkcs1 && padding != RSASignaturePadding.Pss)
      {
        throw new NotSupportedException($"Padding {padding} is not supported");
      }

      return Task.Run(() => this.Pkcs11TokenClientBase.VerifyHashAsync(hash, signature, hashAlgorithm, padding)).GetAwaiter().GetResult();
    }

    #endregion Methods
  }
}