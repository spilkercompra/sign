// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.JSign
{
  using net.jsign.jca;
  using System;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;
  using java.util;
  using java.security.cert;
  using java.io;
  using System.Diagnostics;
  using net.jsign;

  internal class AsymmetricAlgorithmAndCertificateBasedSigningService : SigningService
  {
    #region Fields

    private static readonly Dictionary<string, (HashAlgorithmName digestAlgorithmName, AsymmetricAlgorithmType signingAlgorithmType, RSASignaturePadding? rsaSignaturePadding)> algorithmMapping;

    private readonly X509Chain chain;

    private readonly HashAlgorithmName fileDigestAlgorithm;

    private readonly AsymmetricAlgorithm signingAlgorithm;

    private readonly X509Certificate2 signingCertificate;

    #endregion Fields

    #region Constructors

    static AsymmetricAlgorithmAndCertificateBasedSigningService()
    {
      algorithmMapping = new Dictionary<string, (HashAlgorithmName, AsymmetricAlgorithmType, RSASignaturePadding?)>(StringComparer.OrdinalIgnoreCase)
      {
        { "SHA1withRSA", (HashAlgorithmName.SHA1, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pkcs1) },
        { "SHA256withRSA", (HashAlgorithmName.SHA256, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pkcs1) },
        { "SHA384withRSA", (HashAlgorithmName.SHA384, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pkcs1) },
        { "SHA512withRSA", (HashAlgorithmName.SHA512, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pkcs1) },
        { "SHA256withECDSA", (HashAlgorithmName.SHA256, AsymmetricAlgorithmType.ECDsa, null) },
        { "SHA384withECDSA", (HashAlgorithmName.SHA384, AsymmetricAlgorithmType.ECDsa, null) },
        { "SHA512withECDSA", (HashAlgorithmName.SHA512, AsymmetricAlgorithmType.ECDsa, null) },
        { "SHA256withRSA/PSS", (HashAlgorithmName.SHA256, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pss) },
        { "SHA384withRSA/PSS", (HashAlgorithmName.SHA384, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pss) },
        { "SHA512withRSA/PSS", (HashAlgorithmName.SHA512, AsymmetricAlgorithmType.RSA, RSASignaturePadding.Pss) }
      };
    }

    public AsymmetricAlgorithmAndCertificateBasedSigningService(
      AsymmetricAlgorithm signingAlgorithm,
      X509Certificate2 signingCertificate,
      HashAlgorithmName fileDigestAlgorithm,
      X509Chain chain)
    {
      this.signingAlgorithm = signingAlgorithm;
      this.signingCertificate = signingCertificate;
      this.fileDigestAlgorithm = fileDigestAlgorithm;
      this.chain = chain;
    }

    #endregion Constructors

    #region Methods

    public List aliases()
    {
      var result = new ArrayList();
      result.add(this.signingCertificate.Thumbprint);
      return result;
    }

    public Certificate[] getCertificateChain(string alias)
    {
      Debug.Assert(string.Equals(alias, this.signingCertificate.Thumbprint, StringComparison.Ordinal));

      return this.chain.ChainElements
              .Select(ce => ce.Certificate)
              .Select(certificateNet => CertificateFactory
                                        .getInstance("X.509")
                                        .generateCertificate(new ByteArrayInputStream(certificateNet.RawData)))
              .ToArray();
    }

    public string getName()
    {
      return nameof(AsymmetricAlgorithmAndCertificateBasedSigningService);
    }

    public SigningServicePrivateKey getPrivateKey(string alias, char[] password)
    {
      Debug.Assert(string.Equals(alias, this.signingCertificate.Thumbprint, StringComparison.Ordinal));

      return new SigningServicePrivateKey(alias, this.signingAlgorithm.SignatureAlgorithm, this);
    }

    public SigningServicePrivateKey getPrivateKey(string alias)
    {
      return this.getPrivateKey(alias, []);
    }

    public byte[] sign(SigningServicePrivateKey sspk, string signingAlgorithmWithDigestAlgorithm, byte[] data)
    {
      if (!algorithmMapping.TryGetValue(signingAlgorithmWithDigestAlgorithm, out var algorithms))
      {
        throw new InvalidOperationException($"Invalid algorithm: {signingAlgorithmWithDigestAlgorithm}");
      }

      if (!algorithms.signingAlgorithmType.IsBaseTypeOf(this.signingAlgorithm))
      {
        throw new InvalidOperationException($"Invalid signing algorithm: {signingAlgorithmWithDigestAlgorithm} ./. {this.signingAlgorithm.GetType().Name}");
      }

      var digestAlgorithm = DigestAlgorithm.of(algorithms.digestAlgorithmName.Name);
      var digest = digestAlgorithm.getMessageDigest().digest(data);
     
      switch (this.signingAlgorithm)
      {
        case RSA rsa:
          return rsa.SignHash(digest, this.fileDigestAlgorithm, algorithms.rsaSignaturePadding!);

        case ECDsa ecdsa:
          return ecdsa.SignHash(digest);

        default:
          throw new InvalidOperationException($"Invalid SigningAlgorithm: {this.signingAlgorithm.SignatureAlgorithm}");
      }
    }

    #endregion Methods

    #region Classes

    private class AsymmetricAlgorithmType
    {
      #region Constructors

      static AsymmetricAlgorithmType()
      {
        RSA = new AsymmetricAlgorithmType(typeof(RSA));
        ECDsa = new AsymmetricAlgorithmType(typeof(ECDsa));
      }

      private AsymmetricAlgorithmType(Type type)
      {
        this.Type = type;
      }

      #endregion Constructors

      #region Properties

      public static AsymmetricAlgorithmType ECDsa { get; }
      public static AsymmetricAlgorithmType RSA { get; }
      public Type Type { get; }

      public bool IsBaseTypeOf(AsymmetricAlgorithm instance)
      {
        return this.Type.IsAssignableFrom(instance.GetType());
      }

      #endregion Properties
    }

    #endregion Classes
  }
}