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

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using static ARSoft.Tools.Net.Dns.TlsServerTransport;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   A transport used by a server using tls communication
/// </summary>
public class TlsServerTransport : TcpServerTransportBase<TlsServerTransport>
{
	internal readonly SslServerAuthenticationOptions SslServerAuthenticationOptions;

	/// <summary>
	///   The default port of TCP DNS communication
	/// </summary>
	public const int DEFAULT_PORT = 853;

	/// <summary>
	///   The transport protocol this transport is using
	/// </summary>
	public override TransportProtocol TransportProtocol => TransportProtocol.Tls;

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindAddress">The IP address on which the transport should listen</param>
	/// <param name="sslServerAuthenticationOptions">The ssl connection property bag</param>
	/// <param name="timeout">The read an write timeout in milliseconds</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TlsServerTransport(IPAddress bindAddress, SslServerAuthenticationOptions sslServerAuthenticationOptions, int timeout = 5000, int keepAlive = 120000)
		: this(new IPEndPoint(bindAddress, DEFAULT_PORT), sslServerAuthenticationOptions, timeout, keepAlive) { }

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindEndPoint">The IP endpoint on which the transport should listen</param>
	/// <param name="sslServerAuthenticationOptions">The ssl connection property bag</param>
	/// <param name="timeout">The read an write timeout in milliseconds</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TlsServerTransport(IPEndPoint bindEndPoint, SslServerAuthenticationOptions sslServerAuthenticationOptions, int timeout = 5000, int keepAlive = 120000)
		: base(bindEndPoint, timeout, keepAlive)
	{
		SslServerAuthenticationOptions = sslServerAuthenticationOptions;
	}

	protected override TcpServerConnectionBase CreateConnection(TcpClient client, CancellationToken token)
	{
		return new TlsServerConnection(this, client);
	}

	private class TlsServerConnection : TcpServerConnectionBase
	{
		public TlsServerConnection(TlsServerTransport transport, TcpClient client) : base(transport, client) { }

		protected override async Task<Stream?> GetStreamFromClientAsync(CancellationToken token)
		{
			var sslStream = new SslStream(Client.GetStream(), false);
			await sslStream.AuthenticateAsServerAsync(TransportInternal.SslServerAuthenticationOptions, token);
			return sslStream;
		}
	}
}