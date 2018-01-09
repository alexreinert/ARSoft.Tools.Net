#region Copyright and License
// Copyright 2010..2017 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion
using System;
using System.Threading;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns
{
    /// <summary>
    /// Reusable TCP connection object
    /// </summary>
    internal class ReusableTcpConnection : IDisposable
    {
        /// <summary>
        /// Connection IDLE timeout
        /// </summary>
        private int idleTimeout;

        /// <summary>
        /// Task cancellation token
        /// </summary>
        private CancellationTokenSource cancellationToken;

        /// <summary>
        /// Private TCP client
        /// </summary>
        private System.Net.Sockets.TcpClient client;

        /// <summary>
        /// Flag: Has Dispose already been called?
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="ReusableTcpConnection" /> class
        /// </summary>
        /// <param name="idleTimeout">Connection IDLE timeout</param>
        public ReusableTcpConnection(int idleTimeout = 5000)
        {
            if (idleTimeout <= 0)
            {
                idleTimeout = 5000;
            }

            this.idleTimeout = idleTimeout;
            this.cancellationToken = new CancellationTokenSource();
        }

        /// <summary>
        ///   Gets or sets the TCP client.
        /// </summary>
        public System.Net.Sockets.TcpClient Client
        {
            get
            {
                return this.client;
            }

            set
            {
                if ((this.client == null || !ReferenceEquals(this.client, value)) && value != null)
                {
                    Task.Run(() => idleTester());
                }

                this.client = value;
            }
        }

        /// <summary>
        ///   Gets or sets the TCP connection stream.
        /// </summary>
        public System.IO.Stream Stream { get; set; }

        /// <summary>
        ///   Gets or sets the DateTime when the connection was last used.
        /// </summary>
        public System.DateTime LastUsed { get; set; }

        /// <summary>
        /// Public implementation of Dispose pattern callable by consumer
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected implementation of Dispose pattern.
        /// </summary>
        /// <param name="disposing">Already has been disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (this.disposed)
            {
                return;
            }

            if (disposing)
            {
                this.cancellationToken.Cancel();
            }

            this.disposed = true;
        }

        /// <summary>
        /// Connection idle tester thread
        /// </summary>
        private async void idleTester()
        {
            while (true)
            {
                try
                {
                    await Task.Delay(this.idleTimeout, this.cancellationToken.Token);
                }
                catch (System.Exception)
                {
                }

                if (this.cancellationToken.IsCancellationRequested || (System.DateTime.UtcNow - this.LastUsed).TotalMilliseconds >= this.idleTimeout)
                {
                    try
                    {
                        this.Stream?.Dispose();
                        this.Client?.Close();
                    }
                    catch (System.Exception)
                    {
                    }

                    break;
                }
            }
        }
    }
}
