// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.WebApi
{
  internal interface IWebApiClient<T>
  {
    static abstract T Create(string baseUrl, HttpClient httpClient);
  }
}
