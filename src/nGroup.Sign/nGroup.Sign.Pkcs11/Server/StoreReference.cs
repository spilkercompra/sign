// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Server
{
  using Net.Pkcs11Interop.HighLevelAPI;
  using Net.Pkcs11Interop.X509Store;

  internal class StoreReference : IAquireRelease
  {
    #region Fields

    private ulong refCount = 0;

    #endregion Fields

    #region Constructors

    public StoreReference(Pkcs11X509Store store, IPkcs11Library library, MultipleTokenSimplePinProvider pinProvider)
    {
      this.Pkcs11X509Store = store;
      this.IPkcs11Library = library;
      this.PinProvider = pinProvider;
    }

    #endregion Constructors

    #region Properties

    public IPkcs11Library IPkcs11Library { get; }
    public MultipleTokenSimplePinProvider PinProvider { get; }
    public Pkcs11X509Store Pkcs11X509Store { get; }
    public ulong RefCount { get => this.refCount; set => this.refCount = value; }

    #endregion Properties

    #region Methods

    public void Aquire()
    {
      Interlocked.Increment(ref this.refCount);
    }

    public void Release()
    {
      Interlocked.Decrement(ref this.refCount);

      // https://stackoverflow.com/a/50955389
      //
      // PKCS#11 defines an application as a single process with single address space and one or multiple threads of control running in it.
      // Any application becomes a "Cryptoki application" by initializing PKCS#11 library in one of its threads with a call to C_Initialize function.
      //
      // After the library has been initialized, the application can call other functions of PKCS#11 API. When the application is done using PKCS#11 API,
      // it finalizes PKCS#11 library with a call to C_Finalize function and ceases to be a "Cryptoki application".
      // From application perspective, PKCS#11 library initialization and finalization are global events,
      // so it is crucial to ensure that one thread does not finalize library while other threads are still working with it.
      //
      // PKCS#11 function C_Initialize is called in constructor of HighLevelAPI.Pkcs11 class and C_Finalize function is called when instance of HighLevelAPI.Pkcs11 class is disposed.
      // It is crucial to ensure that two instances of this class working with same PKCS#11 library do not overlap each other.
      // My guess is that you are using more than one instance and you dispose it while you are still trying to use the other.
    }

    #endregion Methods
  }
}