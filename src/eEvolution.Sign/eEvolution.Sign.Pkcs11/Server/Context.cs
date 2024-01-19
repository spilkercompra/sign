// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  internal class Context<T> : IDisposable where T : class, IAquireRelease
  {
    #region Fields

    private int disposed;

    #endregion Fields

    #region Constructors

    public Context(T instance)
    {
      this.Instance = instance;
      this.Instance.Aquire();
    }

    #endregion Constructors

    #region Properties

    public T Instance { get; }

    #endregion Properties

    #region Methods

    public void Dispose()
    {
      var disposed = Interlocked.Exchange(ref this.disposed, 1);
      if (disposed == 0)
      {
        this.Instance.Release();
      }
    }

    #endregion Methods
  }
}