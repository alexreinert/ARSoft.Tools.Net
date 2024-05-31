#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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

using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   A transport used by a client using tcp communication
	/// </summary>
	public class TcpClientTransport : TcpClientTransportBase<TcpClientTransport>
	{
		/// <summary>
		///   The default port of TCP DNS communication
		/// </summary>
		public const int DEFAULT_PORT = 53;

		/// <summary>
		///   Creates a new instance of the TcpClientTransport
		/// </summary>
		/// <param name="port">The port to be used</param>
		public TcpClientTransport(int port = DEFAULT_PORT)
			: base(port) { }

		protected override Task<Stream?> GetStreamAsync(TcpClient client, CancellationToken token)
		{
			return Task.FromResult<Stream?>(client.GetStream());
		}
	}
}