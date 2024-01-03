// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.Server
{
  using Net.Pkcs11Interop.X509Store;

  internal class CertificateReference : IAquireRelease
  {
    #region Fields

    private ulong refCount;

    #endregion Fields

    #region Constructors

    public CertificateReference(Pkcs11X509Certificate pkcs11Certificate, Context<StoreReference> storeReference)
    {
      this.Pkcs11X509Certificate = pkcs11Certificate;
      this.StoreReference = storeReference;
    }

    #endregion Constructors

    #region Properties

    public Pkcs11X509Certificate Pkcs11X509Certificate { get; }
    public ulong RefCount { get => this.refCount; }
    public Context<StoreReference> StoreReference { get; }

    #endregion Properties

    #region Methods

    public void Aquire()
    {
      Interlocked.Increment(ref this.refCount);
    }

    public void Release()
    {
      Interlocked.Decrement(ref this.refCount);
    }

    #endregion Methods
  }
}