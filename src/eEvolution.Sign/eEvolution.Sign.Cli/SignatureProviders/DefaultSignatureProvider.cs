// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Cli.SignatureProviders
{
    using global::Sign.Core;
    using Microsoft.Extensions.DependencyInjection;
    using System;

    internal class DefaultSignatureProvider<T> : IDefaultSignatureProvider where T : ISignatureProvider
    {
        public ISignatureProvider SignatureProvider { get; }

        // Dependency injection requires a public constructor.
        public DefaultSignatureProvider(IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(serviceProvider, nameof(serviceProvider));

            foreach (ISignatureProvider signatureProvider in serviceProvider.GetServices<ISignatureProvider>())
            {
                if (signatureProvider is T)
                {
                    SignatureProvider = signatureProvider;
                    return;
                }
            }

            throw new InvalidOperationException();
        }

        public bool CanSign(FileInfo file)
        {
            return SignatureProvider.CanSign(file);
        }

        public Task SignAsync(IEnumerable<FileInfo> files, SignOptions options)
        {
            return SignatureProvider.SignAsync(files, options);
        }
    }
}
