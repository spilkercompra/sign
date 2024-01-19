// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using System;
  using System.IO.Hashing;
  using System.Text;

  /// <summary>
  /// Zur zusätzlichen Absicherung, dass die Einträge in eEvolution.Sign.Pkcs11.appsettings.json mit den Aufrufparametern übereinstimmen
  /// und nicht versehentlich mit dem falschen Passwort-Eintrag aufgerufen und das Token gesperrt wird.
  /// </summary>
  internal class SimpleClientSecret
  {
    #region Methods

    internal static string ComputeClientSecret(
      string id,
      string clientId,
      string tokenId,
      string tokenPin,
      string secret = "secret",
      string salt = "salt")
    {
      var normalizedInput = string.Join('\0', id.ToLowerInvariant(), clientId.ToLowerInvariant(), tokenId.ToLowerInvariant(), tokenPin, secret, salt);
      var inputBytes = Encoding.UTF8.GetBytes(normalizedInput);
      var hash = XxHash64.Hash(inputBytes);
      var clientSecret = Convert.ToBase64String(hash).TrimEnd('=');
      return clientSecret;
    }

    internal static (string id, string clientId, string clientSecret) FromCredential(string credential)
    {
      var credentialParts = credential
                            .Split('&')
                            .Select(item => Uri.UnescapeDataString(item))
                            .ToArray();

      var result = credentialParts switch
      {
        [var id, var clientId, var clientSecret, ..] => (id, clientId, clientSecret),
        [var id, var clientId] => (id, clientId, ""),
        [var id] => (id, "", ""),
        _ => ("", "", "")
      };

      return result;
    }

    internal static string ToCredential(string id, string clientId, string clientSecret)
    {
      var credential = $"{Uri.EscapeDataString(id)}&{Uri.EscapeDataString(clientId)}&{Uri.EscapeDataString(clientSecret)}";
      return credential;
    }

    internal static bool VerifyClientSecret(
      string clientSecret,
      string id,
      string clientId,
      string tokenId,
      string tokenPin,
      string secret = "secret",
      string salt = "salt")
    {
      var computedSecret = ComputeClientSecret(id, clientId, tokenId, tokenPin, secret, salt);
      return clientSecret == computedSecret;
    }

    #endregion Methods
  }
}