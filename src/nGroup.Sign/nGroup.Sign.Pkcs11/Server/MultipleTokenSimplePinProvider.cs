// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Server
{
  using Net.Pkcs11Interop.X509Store;

  internal class MultipleTokenSimplePinProvider : IPinProvider
  {
    #region Fields

    private static GetPinResult CancelGetPinResult = new GetPinResult(cancel: true, null);

    #endregion Fields

    #region Constructors

    public MultipleTokenSimplePinProvider(Dictionary<string, byte[]> tokenIdsAndTokenPins)
    {
      this.TokenIdsAndTokenPins = tokenIdsAndTokenPins;
    }

    #endregion Constructors

    #region Properties

    public Dictionary<string, byte[]> TokenIdsAndTokenPins { get; }

    private AsyncLocal<ulong> IsInCancelEnterPinScope { get; } = new AsyncLocal<ulong>();

    #endregion Properties

    #region Methods

    public GetPinResult GetKeyPin(Pkcs11X509StoreInfo storeInfo, Pkcs11SlotInfo slotInfo, Pkcs11TokenInfo tokenInfo, Pkcs11X509CertificateInfo certificateInfo)
    {
      return GetTokenPin(storeInfo, slotInfo, tokenInfo);
    }

    public GetPinResult GetTokenPin(Pkcs11X509StoreInfo storeInfo, Pkcs11SlotInfo slotInfo, Pkcs11TokenInfo tokenInfo)
    {
      var isInCancelEnterPinScope = this.IsInCancelEnterPinScope.Value;
      if (isInCancelEnterPinScope > 0)
      {
        return CancelGetPinResult;
      }

      var tokenFound = this.TokenIdsAndTokenPins.TryGetValue(tokenInfo.SerialNumber, out byte[]? pin);
      var cancel = !tokenFound || pin == null;
      return new GetPinResult(cancel, pin);
    }

    public IDisposable UseCancelEnterPin()
    {
      return new CancelEnterPinScope(this);
    }

    #endregion Methods

    #region Classes

    private class CancelEnterPinScope : IDisposable
    {
      #region Constructors

      public CancelEnterPinScope(MultipleTokenSimplePinProvider pinProvider)
      {
        this.PinProvider = pinProvider;
        this.PinProvider.IsInCancelEnterPinScope.Value++;
      }

      #endregion Constructors

      #region Properties

      public MultipleTokenSimplePinProvider PinProvider { get; }

      #endregion Properties

      #region Methods

      public void Dispose()
      {
        this.PinProvider.IsInCancelEnterPinScope.Value--;
      }

      #endregion Methods
    }

    #endregion Classes
  }
}