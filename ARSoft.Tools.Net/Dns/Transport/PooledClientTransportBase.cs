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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Abstract implementation of a pooled client transport
	/// </summary>
	public abstract class PooledClientTransportBase : IClientTransport
	{
		private readonly Dictionary<IPEndPoint, IPoolableClientConnection> _pool = new();
		private readonly int _port;

		/// <summary>
		///   The maximum allowed size of queries in bytes
		/// </summary>
		public abstract ushort MaximumAllowedQuerySize { get; }

		/// <summary>
		///   Returns a value indicating if the transport is reliable
		/// </summary>
		public abstract bool SupportsReliableTransfer { get; }

		/// <summary>
		///   Returns a value indicating if the transport supports multicast communication
		/// </summary>
		public abstract bool SupportsMulticastTransfer { get; }

		/// <summary>
		///   Returns a value indicating if the transport supports pooled connections
		/// </summary>
		public bool SupportsPooledConnections => true;

		protected PooledClientTransportBase(int port)
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
			IPoolableClientConnection? connection = ConnectInternal(endpointInfo, queryTimeout);
			return connection == null ? null : new PooledClientConnection(this, new IPEndPoint(endpointInfo.DestinationAddress, _port), connection);
		}

		protected abstract IPoolableClientConnection? ConnectInternal(DnsClientEndpointInfo endpointInfo, int queryTimeout);

		/// <summary>
		///   Creates a new connection to a server
		/// </summary>
		/// <param name="endpointInfo">The endpoint to connect to</param>
		/// <param name="queryTimeout">The query timeout in milliseconds</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>A connection to the specified server or null, if the connection could not be established</returns>
		public async Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = new())
		{
			IPoolableClientConnection? connection = await ConnectInternalAsync(endpointInfo, queryTimeout, token);
			return connection == null ? null : new PooledClientConnection(this, new IPEndPoint(endpointInfo.DestinationAddress, _port), connection);
		}

		protected abstract Task<IPoolableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token);

		/// <summary>
		///   Gets connection from the pool
		/// </summary>
		/// <param name="endpointInfo">The endpoint of the connection</param>
		/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
		public IClientConnection? GetPooledConnection(DnsClientEndpointInfo endpointInfo)
		{
			var endPoint = new IPEndPoint(endpointInfo.DestinationAddress, _port);

			if (GetFromPool(endPoint, out var connection))
			{
				if (connection!.IsAlive)
				{
					return new PooledClientConnection(this, endPoint, connection);
				}
				else
				{
					try
					{
						connection.Dispose();
					}
					catch { }
				}
			}

			return null;
		}

		private bool GetFromPool(IPEndPoint endPoint, out IPoolableClientConnection? connection)
		{
			lock (_pool)
			{
				if (_pool.TryGetValue(endPoint, out connection))
				{
					_pool.Remove(endPoint);
					return true;
				}
				else
				{
					return false;
				}
			}
		}

		private void PutToPool(IPEndPoint endPoint, IPoolableClientConnection connection)
		{
			if (connection.IsFaulty)
			{
				try
				{
					connection.Dispose();
				}
				catch { }
			}
			else
			{
				lock (_pool)
				{
					_pool[endPoint] = connection;
				}
			}
		}

		public void Dispose()
		{
			lock (_pool)
			{
				foreach (var connection in _pool.Values)
				{
					try
					{
						connection.Dispose();
					}
					catch { }
				}

				_pool.Clear();
			}
		}

		private class PooledClientConnection : IClientConnection
		{
			private readonly PooledClientTransportBase _transport;
			private readonly IPEndPoint _endPoint;
			private readonly IPoolableClientConnection _connection;

			public PooledClientConnection(PooledClientTransportBase transport, IPEndPoint endPoint, IPoolableClientConnection connection)
			{
				_transport = transport;
				_endPoint = endPoint;
				_connection = connection;
			}

			public IClientTransport Transport => _transport;

			public bool Send(DnsRawPackage package)
			{
				return _connection.Send(package);
			}

			public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = new())
			{
				return _connection.SendAsync(package, token);
			}

			public DnsReceivedRawPackage? Receive()
			{
				return _connection.Receive();
			}

			public Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = new())
			{
				return _connection.ReceiveAsync(token);
			}

			public bool IsFaulty => _connection.IsFaulty;

			public void MarkFaulty()
			{
				_connection.MarkFaulty();
			}

			public void Dispose()
			{
				_transport.PutToPool(_endPoint, _connection);
			}
		}
	}
}