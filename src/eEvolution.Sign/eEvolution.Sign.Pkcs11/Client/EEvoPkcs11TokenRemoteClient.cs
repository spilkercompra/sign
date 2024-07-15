﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Client
{
  using eEvolution.Sign.Pkcs11.Server;
  using eEvolution.Sign.Pkcs11.WebApi;
  using System;
  using System.Net;

  internal class EEvoPkcs11TokenRemoteClient<T> : EEvoPkcs11TokenClientBase where T : IEEvoPkcs11TokenAccessApi, IWebApiClient<T>
  {
    #region Constructors

    static EEvoPkcs11TokenRemoteClient()
    {
      var handler = new SocketsHttpHandler
      {
        PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
        Credentials = CredentialCache.DefaultNetworkCredentials
      };
      SharedHttpClient = new HttpClient(handler);
    }

    #endregion Constructors

    #region Properties

    private static HttpClient SharedHttpClient { get; }

    #endregion Properties

    #region Methods

    public override void Initialize(Uri keyVaultUrl, string credential, string certificateName)
    {
      base.Initialize(keyVaultUrl, credential, certificateName);
      this.TokenAccessApi = T.Create(keyVaultUrl.ToString(), SharedHttpClient);
    }

    #endregion Methods
  }
}