#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
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

using System.Net.Security;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   A transport used by a client using tls communication
/// </summary>
public class TlsClientTransport : TcpClientTransportBase<TlsClientTransport>
{
	private readonly SslClientAuthenticationOptions _sslClientAuthenticationOptions;

	/// <summary>
	///   The default port of TLS DNS communication
	/// </summary>
	public const int DEFAULT_PORT = 853;

	/// <summary>
	///   Creates a new instance of the TlsClientTransport
	/// </summary>
	/// <param name="sslClientAuthenticationOptions">Options for SSL Client Authentication</param>
	/// <param name="port">The port to be used</param>
	public TlsClientTransport(SslClientAuthenticationOptions sslClientAuthenticationOptions, int port = DEFAULT_PORT)
		: base(port)
	{
		_sslClientAuthenticationOptions = sslClientAuthenticationOptions;
	}

	protected override async Task<Stream?> GetStreamAsync(TcpClient client, CancellationToken token)
	{
		var stream = new SslStream(client.GetStream(), false);

		await stream.AuthenticateAsClientAsync(_sslClientAuthenticationOptions, token);

		return stream;
	}
}