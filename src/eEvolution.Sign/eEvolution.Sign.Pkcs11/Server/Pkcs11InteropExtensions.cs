// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using Net.Pkcs11Interop.Common;
  using Net.Pkcs11Interop.HighLevelAPI;
  using System;
  using System.Collections.Generic;
  using System.Security.Cryptography.X509Certificates;

  internal static class Pkcs11InteropExtensions
  {
    #region Methods

    public static IEnumerable<CertificateInfo> GetCertificateInfosWithoutPinLogin(this ISlot slot)
    {
      var tokenOk = slot.GetSlotInfo().SlotFlags.TokenPresent;
      if (!tokenOk)
      {
        yield break;
      }

      var tokenInfo = slot.GetTokenInfo();
      tokenOk = tokenOk && tokenInfo.TokenFlags.TokenInitialized;
      if (!tokenOk)
      {
        yield break;
      }

      using (var session = slot.OpenSession(SessionType.ReadOnly))
      {
        List<IObjectAttribute> attributes = new List<IObjectAttribute>
      {
        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, value: true),
        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
      };

        foreach (var certHandle in session.FindAllObjects(attributes))
        {
          var certificateInfo = GetCertificateInfo(certHandle, session);
          if (certificateInfo != null)
          {
            certificateInfo = certificateInfo with { TokenSerialNumber = tokenInfo.SerialNumber };
            yield return certificateInfo;
          }
        }
      }
    }

    private static CertificateInfo? GetCertificateInfo(IObjectHandle certHandle, ISession session)
    {
      List<IObjectAttribute> attributeValue = session.GetAttributeValue(certHandle, new List<CKA>
      {
        CKA.CKA_ID,
        CKA.CKA_LABEL,
        CKA.CKA_VALUE
      });

      var rawData = attributeValue[2].GetValueAsByteArray();
      if (rawData == null)
      {
        return null;
      }

      var id = BitConverter.ToString(attributeValue[0].GetValueAsByteArray() ?? new byte[0]).Replace("-", "");
      var label = attributeValue[1].GetValueAsString() ?? string.Empty;
      var certificate = new X509Certificate2(rawData);

      var pem = certificate.ExportCertificatePem();
      certificate = X509Certificate2.CreateFromPem(pem);

      return new CertificateInfo()
      {
        Issuer = certificate.Issuer,
        NotAfter = certificate.NotAfter,
        NotBefore = certificate.NotBefore,
        Pem = pem,
        HumanReadableData = certificate.ToString(true),
        Subject = certificate.Subject,
        Thumbprint = certificate.Thumbprint,
        TokenCertificateId = id,
        TokenCertificateLabel = label
      };
    }

    #endregion Methods
  }
}