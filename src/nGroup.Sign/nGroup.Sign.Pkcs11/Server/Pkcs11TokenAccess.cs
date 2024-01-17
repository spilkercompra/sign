// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Server
{
  using Net.Pkcs11Interop.Common;
  using Net.Pkcs11Interop.HighLevelAPI;
  using Net.Pkcs11Interop.X509Store;
  using Polly;
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Reflection;
  using System.Security.Cryptography;
  using System.Security.Cryptography.X509Certificates;
  using ConvertUtils = nGroup.Sign.Pkcs11.ConvertUtils;

  internal static partial class Pkcs11TokenAccess
  {
    #region Fields

    private static readonly Pkcs11TokenAccessCache cache;
    private static readonly Pkcs11TokenAccessOptions options;
    private static readonly ResiliencePipeline retry;

    #endregion Fields

    #region Constructors

    static Pkcs11TokenAccess()
    {
      options = LoadOptions();
      cache = new Pkcs11TokenAccessCache();
      retry = new ResiliencePipelineBuilder()
              .AddRetry(new()
              {
                ShouldHandle = new PredicateBuilder()
                                .Handle<Pkcs11Exception>()
                                .Handle<CertificateNotFoundException>(_ =>
                                {
                                  return CheckIfNoTokenPresent();
                                }),
                OnRetry = args =>
                {
                  ReleaseCache();
                  return ValueTask.CompletedTask;
                },
                MaxRetryAttempts = 1,
                Delay = TimeSpan.Zero
              }).Build();
    }

    #endregion Constructors

    #region Methods

    public static byte[] GetCertificate(string credential, string certificateThumbprint)
    {
      return retry.Execute(() =>
      {
        using (var pkcs11CertificateContext = CreatePkcs11CertificateContext(credential, certificateThumbprint))
        {
          var pkcs11Certificate = pkcs11CertificateContext.Instance.Pkcs11X509Certificate;
          var cert = pkcs11Certificate.Info.ParsedCertificate;
          var result = cert.Export(X509ContentType.Cert);
          return result;
        }
      });
    }

    public static TokenInfos[] GetTokenInfos()
    {
      return retry.Execute(() =>
      {
        var storeContexts = CreateStoreContexts();
        try
        {
          var count = storeContexts.Length;
          var result = new TokenInfos[count];

          for (int i = 0; i < count; i++)
          {
            using (var storeContext = storeContexts[i])
            using (storeContext.Instance.PinProvider.UseCancelEnterPin())
            {
              var pkcs11Library = storeContext.Instance.IPkcs11Library;

              var libraryInfo = pkcs11Library.GetInfo();
              var infos = new { Library = libraryInfo, Slots = new List<ISlotInfo>(), Tokens = new List<ITokenInfo>() };

              foreach (var slot in pkcs11Library.GetSlotList(SlotsType.WithTokenPresent))
              {
                var slotInfo = slot.GetSlotInfo();
                infos.Slots.Add(slotInfo);

                if (slotInfo.SlotFlags.TokenPresent)
                {
                  var tokenInfo = slot.GetTokenInfo();
                  infos.Tokens.Add(tokenInfo);
                }
              }

              result[i] = ConvertUtils.CloneConverted<TokenInfos>(infos);
            }
          }

          return result;
        }
        finally
        {
          foreach (var storeContext in storeContexts)
          {
            storeContext.Dispose();
          }
        }
      });
    }

    public static byte[] RsaSignHash(
      string credential,
      string certificateThumbprint,
      byte[] hash,
      HashAlgorithmName hashAlgorithmName,
      RSASignaturePadding signaturePadding)
    {
      return retry.Execute(() =>
      {
        using (var pkcs11CertificateContext = CreatePkcs11CertificateContext(credential, certificateThumbprint))
        {
          var pkcs11Certificate = pkcs11CertificateContext.Instance.Pkcs11X509Certificate;
          using (var rsa = pkcs11Certificate.GetRSAPrivateKey())
          {
            var result = rsa.SignHash(hash, hashAlgorithmName, signaturePadding);
            return result;
          }
        }
      });
    }

    public static bool RsaVerifyHash(
     string credential,
     string certificateThumbprint,
     byte[] hash,
     byte[] signature,
     HashAlgorithmName hashAlgorithmName,
     RSASignaturePadding signaturePadding)
    {
      return retry.Execute(() =>
      {
        using (var pkcs11CertificateContext = CreatePkcs11CertificateContext(credential, certificateThumbprint))
        {
          var pkcs11Certificate = pkcs11CertificateContext.Instance.Pkcs11X509Certificate;
          using (var rsa = pkcs11Certificate.GetRSAPrivateKey())
          {
            var result = rsa.VerifyHash(hash, signature, hashAlgorithmName, signaturePadding);
            return result;
          }
        }
      });
    }

    private static bool CheckIfNoTokenPresent()
    {
      var storeContexts = CreateStoreContexts();
      try
      {
        return storeContexts.Any(sc => sc.Instance.Pkcs11X509Store.Slots.All(sl => sl.Token == null));
      }
      finally
      {
        foreach (var storeContext in storeContexts)
        {
          storeContext.Dispose();
        }
      }
    }

    private static Context<CertificateReference> CreatePkcs11CertificateContext(string credential, string certificateThumbprint)
    {
      var request = credential + certificateThumbprint;
      var certificateReference = default(CertificateReference);

      lock (cache)
      {
        if (!cache.Certificates.TryGetValue(request, out certificateReference))
        {
          ValidateTokenHealth();
          ValidateCredentials(credential);
          var validateCredentialsPredicate = createValidateCredentialsPredicate(credential);

          certificateReference = GetPkcs11Certificate(certificateThumbprint, privateKeyRequired: true, predicate: validateCredentialsPredicate);
          cache.Certificates[request] = certificateReference;
        }
      }

      return new Context<CertificateReference>(certificateReference);

      static Func<Pkcs11X509StoreInfo, Pkcs11SlotInfo, Pkcs11TokenInfo, Pkcs11X509CertificateInfo, bool> createValidateCredentialsPredicate(string credential)
      {
        var tokenIdsAndTokenPinsForCredential = GetValidTokenIdsAndTokenPinsForCredential(credential, throwException: false);
        return new Func<Pkcs11X509StoreInfo, Pkcs11SlotInfo, Pkcs11TokenInfo, Pkcs11X509CertificateInfo, bool>(
                                            (_, __, tokenInfo, ____) =>
                                            {
                                              return tokenIdsAndTokenPinsForCredential.ContainsKey(tokenInfo.SerialNumber);
                                            });
      }
    }

    private static Context<StoreReference>[] CreateStoreContexts()
    {
      lock (cache)
      {
        if (!cache.Stores.Any())
        {
          var options = GetOptions();
          var pkcs11LibraryPaths = GetPkcs11LibraryPaths(options);
          var tokenIdsAndTokenPins = GetTokenIdsAndTokenPins(options);
          foreach (var pkcs11LibraryPath in pkcs11LibraryPaths)
          {
            if (!cache.Stores.TryGetValue(pkcs11LibraryPath, out var storeReference))
            {
              var pinProvider = new MultipleTokenSimplePinProvider(tokenIdsAndTokenPins);
              var store = new Pkcs11X509Store(pkcs11LibraryPath, pinProvider);
              var library = getHighLevelAPILibraryFromStore(store);
              storeReference = new StoreReference(store, library, pinProvider);
              cache.Stores[pkcs11LibraryPath] = storeReference; ;
            }
          }
        }

        return cache.Stores.Values.Select(storeReference => new Context<StoreReference>(storeReference)).ToArray();
      }

      static IPkcs11Library getHighLevelAPILibraryFromStore(Pkcs11X509Store store)
      {
        var storeContext = typeof(Pkcs11X509Store)
                          .GetField("_storeContext", BindingFlags.NonPublic | BindingFlags.Instance)!
                          .GetValue(store)!;
        var library = storeContext
                      .GetType()
                      .GetProperty("Pkcs11Library", BindingFlags.NonPublic | BindingFlags.Instance)!
                      .GetValue(storeContext)!;
        return (IPkcs11Library)library;
      }
    }

    private static Pkcs11X509Certificate? FindPkcs11Certificate(
      StoreReference storeReference,
      string certificateThumbprint,
      bool privateKeyRequired,
      Func<Pkcs11X509StoreInfo, Pkcs11SlotInfo, Pkcs11TokenInfo, Pkcs11X509CertificateInfo, bool> predicate)
    {
      var pinProvider = storeReference.PinProvider;
      var tokenIdsAndTokenPins = pinProvider.TokenIdsAndTokenPins;
      var store = storeReference.Pkcs11X509Store;

      var certificates = store
                          .Slots
                          .Where(slot => slot.Token != null)
                          .Where(slot => !privateKeyRequired || tokenIdsAndTokenPins.ContainsKey(slot.Token.Info.SerialNumber))
                          .SelectMany(slot => slot.Token.Certificates.Select(certificate =>
                            new
                            {
                              Store = store,
                              Slot = slot,
                              Token = slot.Token,
                              Certificate = certificate
                            }));

      certificates = certificates
                      .Where(cert => string.Equals(cert.Certificate.Info.ParsedCertificate.Thumbprint, certificateThumbprint, StringComparison.OrdinalIgnoreCase));

      certificates = certificates
                      .Where(cert => predicate?.Invoke(cert.Store.Info, cert.Slot.Info, cert.Token.Info, cert.Certificate.Info) ?? true);

      var pkcs11Certificate = certificates.Select(cert => cert.Certificate).FirstOrDefault();
      return pkcs11Certificate;
    }

    private static Pkcs11TokenAccessOptions GetOptions()
    {
      return options;
    }

    private static CertificateReference GetPkcs11Certificate(string certificateThumbprint, bool privateKeyRequired, Func<Pkcs11X509StoreInfo, Pkcs11SlotInfo, Pkcs11TokenInfo, Pkcs11X509CertificateInfo, bool> predicate)
    {
      var storeContexts = CreateStoreContexts();
      try
      {
        foreach (var storeContext in storeContexts)
        {
          var storeReference = storeContext.Instance;
          var pkcs11Certificate = FindPkcs11Certificate(storeReference, certificateThumbprint, privateKeyRequired, predicate);

          var isValidCertificate = pkcs11Certificate != null
                                   && (!privateKeyRequired || pkcs11Certificate.HasPrivateKeyObject);
          if (isValidCertificate)
          {
            return new CertificateReference(pkcs11Certificate!, new Context<StoreReference>(storeContext.Instance));
          }
        }

        throw new CertificateNotFoundException($"Invalid Certificate Thumbprint: {certificateThumbprint}");
      }
      finally
      {
        foreach (var storeContext in storeContexts)
        {
          storeContext.Dispose();
        }
      }
    }

    private static List<string> GetPkcs11LibraryPaths(Pkcs11TokenAccessOptions options)
    {
      var validPaths = options.Pkcs11LibraryPaths.Where(path => File.Exists(path)).ToList();

      if (!validPaths.Any())
      {
        throw new ArgumentException("No valid Pkcs11LibraryPath found", nameof(options.Pkcs11LibraryPaths));
      }

      return validPaths;
    }

    private static Dictionary<string, byte[]> GetTokenIdsAndTokenPins(Pkcs11TokenAccessOptions options)
    {
      var tokenIdsAndTokenPins = options.TokenIdsAndTokenPins;
      return tokenIdsAndTokenPins.ToDictionary(tokenAndPin => tokenAndPin.Key, tokenAndPin => ConvertUtils.Utf8StringToBytes(tokenAndPin.Value));
    }

    private static Dictionary<string, byte[]> GetValidTokenIdsAndTokenPinsForCredential(string credential, bool throwException)
    {
      var credentials = SimpleClientSecret.FromCredential(credential);

      var options = GetOptions();
      if (!options.CredentialsAndTokenIds.TryGetValue(credentials.id, out var tokenIdsForCredential))
      {
        if (throwException)
        {
          throw new ArgumentException($"Invalid Credentials: {credential}", nameof(credential));
        }
        else
        {
          return new Dictionary<string, byte[]>();
        }
      }

      var tokenIdsAndTokenPins = GetTokenIdsAndTokenPins(options);
      var validTokenIdsAndTokenPinsForCredential = new Dictionary<string, byte[]>();
      foreach (var tokenId in tokenIdsForCredential)
      {
        if (tokenIdsAndTokenPins.TryGetValue(tokenId, out var tokenPin)
           && SimpleClientSecret.VerifyClientSecret(
                credentials.clientSecret,
                credentials.id,
                credentials.clientId,
                tokenId,
                ConvertUtils.BytesToUtf8String(tokenPin)))
        {
          validTokenIdsAndTokenPinsForCredential[tokenId] = tokenPin;
        }
      }

      if (!validTokenIdsAndTokenPinsForCredential.Any())
      {
        if (throwException)
        {
          throw new ArgumentException($"Invalid Credentials: {credential}", nameof(credential));
        }
      }

      return validTokenIdsAndTokenPinsForCredential;
    }

    private static Pkcs11TokenAccessOptions LoadOptions()
    {
      var options = Pkcs11TokenAccessOptions.GetInstance();

      foreach (var entry in options.EnvironmentVariables)
      {
        Environment.SetEnvironmentVariable(entry.Key, entry.Value);
      }

      return options;
    }

    private static void Logout(StoreReference storeReference)
    {
      var store = storeReference.Pkcs11X509Store;
      ;
      var highLevelSlots = storeReference
                          .IPkcs11Library
                          .GetSlotList(SlotsType.WithTokenPresent);
      foreach (var highLevelSlotAPI in highLevelSlots)
      {
        using (var session = highLevelSlotAPI.OpenSession(SessionType.ReadOnly))
        {
          session.Logout();
        }
      }
    }

    private static void ReleaseCache()
    {
      lock (cache)
      {
        var certificates = cache.Certificates.Values.ToArray();
        var stores = cache.Stores.Values.ToArray();

        cache.Certificates.Clear();
        cache.Stores.Clear();

        foreach (var cert in certificates)
        {
          while (cert.RefCount > 0)
          {
            Thread.Sleep(100);
          }

          cert.StoreReference.Dispose();
        }

        foreach (var store in stores)
        {
          while (store.RefCount > 0)
          {
            Thread.Sleep(100);
          }

          store.Pkcs11X509Store.Dispose();
        }
      }
    }

    private static void ValidateCredentials(string credential)
    {
      _ = GetValidTokenIdsAndTokenPinsForCredential(credential, throwException: true);
    }

    private static void ValidateTokenHealth()
    {
      var tokenInfos = GetTokenInfos();
      var isHealthy = !tokenInfos.Any(
                          ti => ti.Tokens.Any(
                            token =>
                            {
                              var flags = token.TokenFlags!;
                              return flags.TokenInitialized
                                  && (flags.UserPinCountLow
                                    || flags.UserPinFinalTry
                                    || flags.UserPinLocked
                                    || flags.UserPinToBeChanged
                                    || flags.SoPinCountLow
                                    || flags.SoPinFinalTry
                                    || flags.SoPinLocked
                                    || flags.SoPinToBeChanged);
                            }));
      if (!isHealthy)
      {
        throw new InvalidOperationException("Token locked?");
      }
    }

    #endregion Methods
  }
}