// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.JSign
{
  using net.jsign.jca;
  using net.jsign;
  using System;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;
  using net.jsign.timestamp;
  using java.io;

  public class JSignSigner : IDisposable
  {
    #region Fields

    private readonly X509Chain _chain;
    private readonly ExistingSignatureHandling _existingSignatureHandling;
    private readonly HashAlgorithmName _fileDigestAlgorithm;
    private readonly AsymmetricAlgorithm _signingAlgorithm;
    private readonly X509Certificate2 _signingCertificate;
    private readonly TimeStampConfiguration _timeStampConfiguration;

    #endregion Fields

    #region Constructors

    /// <summary>
    /// Creates a new instance of <see cref="JSignSigner" />.
    /// </summary>
    /// <param name="signingAlgorithm">
    /// An instance of an asymmetric algorithm that will be used to sign. It must support signing with
    /// a private key.
    /// </param>
    /// <param name="signingCertificate">The X509 public certificate for the <paramref name="signingAlgorithm"/>.</param>
    /// <param name="fileDigestAlgorithm">The digest algorithm to sign the file.</param>
    /// <param name="timeStampConfiguration">The timestamp configuration for timestamping the file. To omit timestamping,
    /// use <see cref="TimeStampConfiguration.None"/>.</param>
    /// <param name="additionalCertificates">Any additional certificates to assist in building a certificate chain.</param>
    public JSignSigner(
      AsymmetricAlgorithm signingAlgorithm,
      X509Certificate2 signingCertificate,
      HashAlgorithmName fileDigestAlgorithm,
      TimeStampConfiguration timeStampConfiguration,
      ExistingSignatureHandling existingSignatureHandling = ExistingSignatureHandling.Skip,
      X509Certificate2Collection? additionalCertificates = null)
    {
      _fileDigestAlgorithm = fileDigestAlgorithm;
      _signingCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
      _timeStampConfiguration = timeStampConfiguration ?? throw new ArgumentNullException(nameof(timeStampConfiguration));
      _existingSignatureHandling = existingSignatureHandling;
      _signingAlgorithm = signingAlgorithm ?? throw new ArgumentNullException(nameof(signingAlgorithm));
      _chain = new X509Chain();

      if (additionalCertificates is not null)
      {
        _chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
      }

      //We don't care about the trustworthiness of the cert. We just want a chain to sign with.
      _chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;

      if (!_chain.Build(signingCertificate))
      {
        throw new InvalidOperationException("Failed to build chain for certificate.");
      }
    }

    #endregion Constructors

    #region Methods

    public void Dispose()
    {
      _chain.Dispose();
    }

    /// <summary>Authenticode signs a file.</summary>
    /// <param name="descriptionUrl">A URL describing the signature or the signer.</param>
    /// <param name="description">The description to apply to the signature.</param>
    /// <param name="path">The path to the file to signed.</param>
    /// <returns>A HRESULT indicating the result of the signing operation. S_OK, or zero, is returned if the signing
    /// operation completed successfully.</returns>
    public int SignFile(ReadOnlySpan<char> path, ReadOnlySpan<char> description, ReadOnlySpan<char> descriptionUrl)
    {
      using (var signable = Signable.of(new File(path.ToString())))
      {
        var skipSignedFiles = _existingSignatureHandling == ExistingSignatureHandling.Skip;
        if (skipSignedFiles
          && IsSigned(signable))
        {
          return 0;
        }

        var signer = CreateAuthenticodeSigner();
        signer = signer.withProgramName(description.ToString())
                       .withProgramURL(descriptionUrl.ToString());

        signer.sign(signable);
        return 0;
      }
    }

    private static bool IsSigned(Signable signable)
    {
      var signatures = signable.getSignatures();
      var hasSignature = !signatures.isEmpty();
      return hasSignature;
    }

    private static DigestAlgorithm ToDigestAlgorithm(HashAlgorithmName fileDigestAlgorithm)
    {
      return fileDigestAlgorithm.Name switch
      {
        nameof(HashAlgorithmName.MD5) => DigestAlgorithm.MD5,
        nameof(HashAlgorithmName.SHA1) => DigestAlgorithm.SHA1,
        nameof(HashAlgorithmName.SHA256) => DigestAlgorithm.SHA256,
        nameof(HashAlgorithmName.SHA384) => DigestAlgorithm.SHA384,
        nameof(HashAlgorithmName.SHA512) => DigestAlgorithm.SHA512,
        _ => throw new ArgumentException($"Invalid HashAlgorithmName: {fileDigestAlgorithm}", nameof(fileDigestAlgorithm))
      };
    }

    private static TimestampingMode ToTimeStampingMode(TimeStampType? type)
    {
      return type == TimeStampType.Authenticode
        ? TimestampingMode.AUTHENTICODE
        : TimestampingMode.RFC3161;
    }

    private AuthenticodeSigner CreateAuthenticodeSigner()
    {
      // init, sonst Exception
      var context = java.security.AccessController.getContext();

      var service = new AsymmetricAlgorithmAndCertificateBasedSigningService(_signingAlgorithm, _signingCertificate, _fileDigestAlgorithm, _chain);

      var provider = new SigningServiceJcaProvider(service);

      var keyStore = java.security.KeyStore.getInstance(service.getName(), provider);

      // init, sonst Exception
      keyStore.load(null, []);

      var signer = new AuthenticodeSigner(keyStore, _signingCertificate.Thumbprint, "dummyPassword")
                    .withSignatureProvider(provider)
                    .withDigestAlgorithm(ToDigestAlgorithm(_fileDigestAlgorithm))
                    ;

      if (_timeStampConfiguration != TimeStampConfiguration.None
        && _timeStampConfiguration.Type != null)
      {
        signer = signer
                 .withTimestamping(true)
                 .withTimestampingAuthority(_timeStampConfiguration.Url)
                 .withTimestampingMode(ToTimeStampingMode(_timeStampConfiguration.Type));
      }

      var replaceSignatures = _existingSignatureHandling == ExistingSignatureHandling.Replace;
      if (replaceSignatures)
      {
        signer = signer.withSignaturesReplaced(true);
      }

      return signer;
    }

    #endregion Methods
  }
}