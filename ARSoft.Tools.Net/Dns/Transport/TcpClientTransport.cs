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

using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   A transport used by a client using tcp communication
	/// </summary>
	public class TcpClientTransport : PooledClientTransportBase
	{
		/// <summary>
		///   The default port of UDP DNS communication
		/// </summary>
		public const int DEFAULT_PORT = 53;

		private readonly int _port;

		/// <summary>
		///   The maximum allowed size of queries in bytes
		/// </summary>
		public override ushort MaximumAllowedQuerySize => UInt16.MaxValue;

		/// <summary>
		///   Returns a value indicating if the transport is reliable
		/// </summary>
		public override bool SupportsReliableTransfer => true;

		/// <summary>
		///   Returns a value indicating if the transport supports multicast communication
		/// </summary>
		public override bool SupportsMulticastTransfer => false;

		/// <summary>
		///   Creates a new instance of the TcpClientTransport
		/// </summary>
		/// <param name="port">The port to be used</param>
		public TcpClientTransport(int port = DEFAULT_PORT)
			: base(port)
		{
			_port = port;
		}

		protected override IPoolableClientConnection? ConnectInternal(DnsClientEndpointInfo endpointInfo, int queryTimeout)
		{
			var tcpClient = new TcpClient(endpointInfo.DestinationAddress.AddressFamily)
			{
				ReceiveTimeout = queryTimeout,
				SendTimeout = queryTimeout
			};

			try
			{
				if (!tcpClient.TryConnect(endpointInfo.DestinationAddress, _port, queryTimeout))
					return null;

				var tcpStream = tcpClient.GetStream();

				return new TcpClientConnection(this, (IPEndPoint) tcpClient.Client.RemoteEndPoint!, (IPEndPoint) tcpClient.Client.LocalEndPoint!, tcpClient, tcpStream);
			}
			catch
			{
				return null;
			}
		}

		protected override async Task<IPoolableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token)
		{
			var tcpClient = new TcpClient(endpointInfo.DestinationAddress.AddressFamily)
			{
				ReceiveTimeout = queryTimeout,
				SendTimeout = queryTimeout
			};

			try
			{
				if (!await tcpClient.TryConnectAsync(endpointInfo.DestinationAddress, _port, queryTimeout, token))
					return null;

				var tcpStream = tcpClient.GetStream();

				return new TcpClientConnection(this, (IPEndPoint) tcpClient.Client.RemoteEndPoint!, (IPEndPoint) tcpClient.Client.LocalEndPoint!, tcpClient, tcpStream);
			}
			catch
			{
				return null;
			}
		}

		private class TcpClientConnection : IPoolableClientConnection
		{
			private readonly TcpClientTransport _transport;

			//private readonly DnsClientEndpointInfo _endpointInfo;
			private readonly IPEndPoint _destinationEndPoint;
			private readonly IPEndPoint _localEndPoint;
			private readonly TcpClient _client;
			private readonly NetworkStream _stream;

			public TcpClientConnection(TcpClientTransport transport, IPEndPoint destinationEndPoint, IPEndPoint localEndPoint, TcpClient client, NetworkStream stream)
			{
				_transport = transport;
				_destinationEndPoint = destinationEndPoint;
				_localEndPoint = localEndPoint;
				_client = client;
				_stream = stream;
			}

			public IClientTransport Transport => _transport;

			public bool Send(DnsRawPackage package)
			{
				if (package.Length > 0)
				{
					try
					{
						_stream.Write(package.ToArraySegment(true));
					}
					catch
					{
						return false;
					}
				}

				return true;
			}

			public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = new())
			{
				if (package.Length > 0)
				{
					try
					{
						await _stream.WriteAsync(package.ToArraySegment(true), token);
					}
					catch
					{
						return false;
					}
				}

				return true;
			}

			public DnsReceivedRawPackage? Receive()
			{
				var buffer = new byte[2];

				try
				{
					if (!TryRead(buffer, 0, 2))
					{
						MarkFaulty();
						return null;
					}

					var tmp = 0;
					var length = DnsMessageBase.ParseUShort(buffer, ref tmp);

					buffer = new byte[length + 2];
					DnsMessageBase.EncodeUShort(buffer, 0, length);

					if (!TryRead(buffer, 2, length))
					{
						MarkFaulty();
						return null;
					}

					return new DnsReceivedRawPackage(buffer, _destinationEndPoint, _localEndPoint);
				}
				catch
				{
					MarkFaulty();
					return null;
				}
			}

			private bool TryRead(byte[] buffer, int offset, int length)
			{
				var readBytes = 0;

				while (readBytes < length)
				{
					if (!_client.IsConnected())
						return false;

					readBytes += _stream.Read(buffer, offset + readBytes, length - readBytes);
				}

				return true;
			}

			public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = new())
			{
				var buffer = new byte[2];

				try
				{
					if (!await TryReadAsync(buffer, 0, 2, token))
					{
						MarkFaulty();
						return null;
					}

					var tmp = 0;
					int length = DnsMessageBase.ParseUShort(buffer, ref tmp);

					buffer = new byte[length + 2];
					DnsMessageBase.EncodeUShort(buffer, 0, (ushort) length);

					if (!await TryReadAsync(buffer, 2, length, token))
					{
						MarkFaulty();
						return null;
					}

					return new DnsReceivedRawPackage(buffer, _destinationEndPoint, _localEndPoint);
				}
				catch
				{
					MarkFaulty();
					return null;
				}
			}

			private async Task<bool> TryReadAsync(byte[] buffer, int offset, int length, CancellationToken token)
			{
				var readBytes = 0;

				while (readBytes < length)
				{
					if (token.IsCancellationRequested || !_client.IsConnected())
						return false;

					try
					{
						readBytes += await _stream.ReadAsync(buffer, offset + readBytes, length - readBytes, token);
					}
					catch
					{
						return false;
					}
				}

				return true;
			}

			public bool IsAlive => !IsFaulty && _client.IsConnected();

			public bool IsFaulty { get; private set; }

			public void MarkFaulty()
			{
				IsFaulty = true;
			}

			public void Dispose()
			{
				try
				{
					_stream.Dispose();
				}
				catch { }

				try
				{
					_client.Close();
				}
				catch { }
			}
		}
	}
}