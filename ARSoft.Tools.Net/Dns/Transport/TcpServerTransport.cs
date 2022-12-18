#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   A transport used by a server using tcp communication
/// </summary>
public class TcpServerTransport : TcpServerTransportBase<TcpServerTransport, TcpServerTransport.TcpServerConnection, NetworkStream>
{
	/// <summary>
	///   The default port of TCP DNS communication
	/// </summary>
	public const int DEFAULT_PORT = 53;

	/// <summary>
	///   The transport protocol this transport is using
	/// </summary>
	public override TransportProtocol TransportProtocol => TransportProtocol.Tcp;

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindAddress">The IP address on which the transport should listen</param>
	/// <param name="timeout">The read an write timeout in milliseconds</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TcpServerTransport(IPAddress bindAddress, int timeout = 5000, int keepAlive = 120000)
		: base(new IPEndPoint(bindAddress, DEFAULT_PORT), timeout, keepAlive) { }

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindEndPoint">The IP éndpoint on which the transport should listen</param>
	/// <param name="timeout">The read an write timeout in milliseconds</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TcpServerTransport(IPEndPoint bindEndPoint, int timeout = 5000, int keepAlive = 120000)
		: base(bindEndPoint, timeout, keepAlive) { }

	protected override TcpServerConnection CreateConnection(TcpClient client)
	{
		return new TcpServerConnection(this, client);
	}

	/// <summary>
	///   The connection which is used to the server using TCP communitions
	/// </summary>
	public class TcpServerConnection : TcpServerTransportBase<TcpServerTransport, TcpServerTransport.TcpServerConnection, NetworkStream>.TcpServerConnectionBase
	{
		internal TcpServerConnection(TcpServerTransport transport, TcpClient client)
			: base(transport, client, client.GetStream()) { }
	}
}