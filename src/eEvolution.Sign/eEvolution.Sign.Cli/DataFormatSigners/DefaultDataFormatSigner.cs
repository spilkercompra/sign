// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Cli.DataFormatSigners
{
    using global::Sign.Core;
    using Microsoft.Extensions.DependencyInjection;
    using System;

    internal class DefaultDataFormatSigner<T> : IDefaultDataFormatSigner where T : IDataFormatSigner
    {
        public IDataFormatSigner Signer { get; }

        // Dependency injection requires a public constructor.
        public DefaultDataFormatSigner(IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(serviceProvider, nameof(serviceProvider));

            foreach (IDataFormatSigner signer in serviceProvider.GetServices<IDataFormatSigner>())
            {
                if (signer is T)
                {
                    Signer = signer;
                    return;
                }
            }

            throw new InvalidOperationException();
        }

        public bool CanSign(FileInfo file)
        {
            return Signer.CanSign(file);
        }

        public Task SignAsync(IEnumerable<FileInfo> files, SignOptions options)
        {
            return Signer.SignAsync(files, options);
        }
    }
}
