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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   A transport used by a client using udp communication
	/// </summary>
	public class UdpClientTransport : IClientTransport
	{
		/// <summary>
		///   The default port of UDP DNS communication
		/// </summary>
		public const int DEFAULT_PORT = 53;

		private readonly int _port;

		/// <summary>
		///   The maximum allowed size of queries in bytes
		/// </summary>
		public ushort MaximumAllowedQuerySize => 512;

		/// <summary>
		///   Returns a value indicating if the transport is reliable
		/// </summary>
		public bool SupportsReliableTransfer => false;

		/// <summary>
		///   Returns a value indicating if the transport supports multicast communication
		/// </summary>
		public bool SupportsMulticastTransfer => false;

		/// <summary>
		///   Returns a value indicating if the transport supports pooled connections
		/// </summary>
		public bool SupportsPooledConnections => false;

		/// <summary>
		///   Creates a new instance of the UdpClientTransport
		/// </summary>
		/// <param name="port">The port to be used</param>
		public UdpClientTransport(int port = DEFAULT_PORT)
		{
			_port = port;
		}

		/// <summary>
		///   Creates a new connection to a server
		/// </summary>
		/// <param name="endpointInfo">The endpoint to connect to</param>
		/// <param name="queryTimeout">The query timeout in milliseconds</param>
		/// <returns>A connection to the specified server or null, if the connection could not be established</returns>
		public IClientConnection? Connect(DnsClientEndpointInfo endpointInfo, int queryTimeout)
		{
			var socket = new Socket(endpointInfo.LocalAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
			{
				ReceiveTimeout = queryTimeout,
				SendTimeout = queryTimeout
			};

			try
			{
				socket.Connect(endpointInfo.DestinationAddress, _port);

				return new UdpClientConnection(this, endpointInfo, socket, queryTimeout);
			}
			catch
			{
				return null;
			}
		}

		/// <summary>
		///   Creates a new connection to a server
		/// </summary>
		/// <param name="endpointInfo">The endpoint to connect to</param>
		/// <param name="queryTimeout">The query timeout in milliseconds</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>A connection to the specified server or null, if the connection could not be established</returns>
		public async Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = new())
		{
			Socket socket = new Socket(endpointInfo.LocalAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
			{
				ReceiveTimeout = queryTimeout,
				SendTimeout = queryTimeout
			};

			try
			{
				await socket.ConnectAsync(endpointInfo.DestinationAddress, _port, token).AsTask().WithTimeout(queryTimeout, token);

				return new UdpClientConnection(this, endpointInfo, socket, queryTimeout);
			}
			catch
			{
				return null;
			}
		}

		/// <summary>
		///   Gets connection from the pool
		/// </summary>
		/// <param name="endpointInfo">The endpoint of the connection</param>
		/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
		public IClientConnection GetPooledConnection(DnsClientEndpointInfo endpointInfo)
		{
			throw new NotSupportedException();
		}

		void IDisposable.Dispose()
		{
			GC.SuppressFinalize(this);
		}

		private class UdpClientConnection : IClientConnection
		{
			private readonly UdpClientTransport _transport;
			private readonly DnsClientEndpointInfo _endpointInfo;
			private readonly Socket _socket;
			private readonly int _queryTimeout;

			public UdpClientConnection(UdpClientTransport transport, DnsClientEndpointInfo endpointInfo, Socket socket, int queryTimeout)
			{
				_transport = transport;
				_endpointInfo = endpointInfo;
				_socket = socket;
				_queryTimeout = queryTimeout;
			}

			public IClientTransport Transport => _transport;

			public bool Send(DnsRawPackage package)
			{
				try
				{
					if (_socket.Send(package.ToArraySegment(false), SocketFlags.None) < package.Length)
					{
						MarkFaulty();
						return false;
					}

					return true;
				}
				catch
				{
					MarkFaulty();
					return false;
				}
			}

			public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = new())
			{
				try
				{
					var sentBytes = await _socket.SendAsync(package.ToArraySegment(false), SocketFlags.None).WithTimeout(_queryTimeout, token);

					if (sentBytes < package.Length)
					{
						MarkFaulty();
						return false;
					}

					return true;
				}
				catch
				{
					MarkFaulty();
					return false;
				}
			}

			public DnsReceivedRawPackage? Receive()
			{
				try
				{
					var buffer = new byte[_socket.ReceiveBufferSize + DnsRawPackage.LENGTH_HEADER_LENGTH];
					var length = _socket.Receive(buffer, DnsRawPackage.LENGTH_HEADER_LENGTH, buffer.Length - DnsRawPackage.LENGTH_HEADER_LENGTH, SocketFlags.None);

					if (length == 0)
					{
						MarkFaulty();
						return null;
					}

					DnsMessageBase.EncodeUShort(buffer, 0, (ushort) length);

					return new DnsReceivedRawPackage(buffer, (IPEndPoint) _socket.RemoteEndPoint!, (IPEndPoint) _socket.LocalEndPoint!);
				}
				catch
				{
					MarkFaulty();
					return null;
				}
			}

			public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = new())
			{
				var buffer = new byte[_socket.ReceiveBufferSize + DnsRawPackage.LENGTH_HEADER_LENGTH];

				try
				{
					var length = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer, DnsRawPackage.LENGTH_HEADER_LENGTH, buffer.Length - DnsRawPackage.LENGTH_HEADER_LENGTH), SocketFlags.None).WithTimeout(_queryTimeout, token);

					if (length == 0)
					{
						MarkFaulty();
						return null;
					}

					DnsMessageBase.EncodeUShort(buffer, 0, (ushort) length);

					return new DnsReceivedRawPackage(buffer, (IPEndPoint) _socket.RemoteEndPoint!, (IPEndPoint) _socket.LocalEndPoint!);
				}
				catch
				{
					MarkFaulty();
					return null;
				}
			}

			public bool IsFaulty { get; private set; }

			public void MarkFaulty()
			{
				IsFaulty = true;
			}

			public void Dispose()
			{
				try
				{
					_socket.Dispose();
				}
				catch { }
			}
		}
	}
}