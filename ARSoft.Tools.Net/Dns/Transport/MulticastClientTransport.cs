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
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   A transport used by a client using multicast udp communication
	/// </summary>
	public class MulticastClientTransport : IClientTransport
	{
		private readonly int _port;
		private static readonly ushort _maximumMessageSize;

		/// <summary>
		///   The maximum allowed size of queries in bytes
		/// </summary>
		public ushort MaximumAllowedQuerySize { get; }

		/// <summary>
		///   Returns a value indicating if the transport is reliable
		/// </summary>
		public bool SupportsReliableTransfer => false;

		/// <summary>
		///   Returns a value indicating if the transport supports multicast communication
		/// </summary>
		public bool SupportsMulticastTransfer => true;

		/// <summary>
		///   Returns a value indicating if the transport supports pooled connections
		/// </summary>
		public bool SupportsPooledConnections => false;

		static MulticastClientTransport()
		{
			try
			{
				_maximumMessageSize = (ushort) NetworkInterface.GetAllNetworkInterfaces()
					.Where(n => n.SupportsMulticast && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback) && (n.OperationalStatus == OperationalStatus.Up) && (n.Supports(NetworkInterfaceComponent.IPv4)))
					.Select(n => n.GetIPProperties())
					.Min(p => Math.Min(p.GetIPv4Properties().Mtu, p.GetIPv6Properties().Mtu));
			}
			catch
			{
				// ignored
			}

			_maximumMessageSize = Math.Max((ushort) 512, _maximumMessageSize);
		}

		/// <summary>
		///   Creates a new instance of the MulticastClientTransport
		/// </summary>
		/// <param name="port">The port to be used</param>
		public MulticastClientTransport(int port)
		{
			_port = port;
			MaximumAllowedQuerySize = _maximumMessageSize;
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
				socket.Bind(new IPEndPoint(endpointInfo.LocalAddress, 0));

				return new MulticastClientConnection(this, endpointInfo, socket, queryTimeout);
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
		public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = new())
		{
			var socket = new Socket(endpointInfo.LocalAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
			{
				ReceiveTimeout = queryTimeout,
				SendTimeout = queryTimeout
			};

			try
			{
				socket.Bind(new IPEndPoint(endpointInfo.LocalAddress, 0));

				return Task.FromResult((IClientConnection?) new MulticastClientConnection(this, endpointInfo, socket, queryTimeout));
			}
			catch
			{
				return Task.FromResult<IClientConnection?>(null);
			}
		}

		/// <summary>
		///   Gets connection from the pool
		/// </summary>
		/// <param name="endpointInfo">The endpoint of the connection</param>
		/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
		public IClientConnection? GetPooledConnection(DnsClientEndpointInfo endpointInfo)
		{
			throw new NotSupportedException();
		}

		void IDisposable.Dispose()
		{
			GC.SuppressFinalize(this);
		}

		private class MulticastClientConnection : IClientConnection
		{
			private readonly MulticastClientTransport _transport;
			private readonly DnsClientEndpointInfo _endpointInfo;
			private readonly Socket _socket;
			private readonly int _queryTimeout;

			public MulticastClientConnection(MulticastClientTransport transport, DnsClientEndpointInfo endpointInfo, Socket socket, int queryTimeout)
			{
				_transport = transport;
				_endpointInfo = endpointInfo;
				_socket = socket;
				_queryTimeout = queryTimeout;
			}

			public IClientTransport Transport => _transport;

			public bool Send(DnsRawPackage package)
			{
				EndPoint serverEndpoint = new IPEndPoint(_endpointInfo.DestinationAddress, _transport._port);

				try
				{
					if (_socket.SendTo(package.ToArraySegment(false), SocketFlags.None, serverEndpoint) < package.Length)
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
					var serverEndpoint = new IPEndPoint(_endpointInfo.DestinationAddress, _transport._port);
					var sentBytes = await _socket.SendToAsync(package.ToArraySegment(false), SocketFlags.None, serverEndpoint).WithTimeout(_queryTimeout, token);

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
					EndPoint serverEndpoint = new IPEndPoint(_socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, _transport._port);

					var buffer = new byte[_socket.ReceiveBufferSize + 2];
					var length = _socket.ReceiveFrom(buffer, 2, buffer.Length - 2, SocketFlags.None, ref serverEndpoint);

					if (length == 0)
					{
						MarkFaulty();
						return null;
					}

					DnsMessageBase.EncodeUShort(buffer, 0, (ushort) length);

					return new DnsReceivedRawPackage(buffer, ((IPEndPoint) serverEndpoint), ((IPEndPoint) _socket.LocalEndPoint!));
				}
				catch
				{
					MarkFaulty();
					return null;
				}
			}

			public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = new CancellationToken())
			{
				var serverEndpoint = new IPEndPoint(_socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, _transport._port);
				var buffer = new byte[_socket.ReceiveBufferSize + 2];

				try
				{
					var receiveRes = await _socket.ReceiveFromAsync(new ArraySegment<byte>(buffer, 2, buffer.Length - 2), SocketFlags.None, serverEndpoint).WithTimeout(_queryTimeout, token);

					if (receiveRes.ReceivedBytes == 0)
					{
						MarkFaulty();
						return null;
					}

					DnsMessageBase.EncodeUShort(buffer, 0, (ushort) receiveRes.ReceivedBytes);

					return new DnsReceivedRawPackage(buffer, ((IPEndPoint) receiveRes.RemoteEndPoint), ((IPEndPoint) _socket.LocalEndPoint!));
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