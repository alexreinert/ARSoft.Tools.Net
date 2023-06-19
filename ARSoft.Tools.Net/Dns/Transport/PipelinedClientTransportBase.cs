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
using System.Threading;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   Abstract implementation of a pipelined client transport
/// </summary>
public abstract class PipelinedClientTransportBase : IClientTransport
{
	private readonly Dictionary<IPAddress, Task<PipelinedClientConnection?>> _pool = new();
	private readonly int _port;

	/// <summary>
	///   The maximum allowed size of queries in bytes
	/// </summary>
	public abstract ushort MaximumAllowedQuerySize { get; }

	/// <summary>
	///   Returns a value indicating if the transport is reliable
	/// </summary>
	public bool SupportsReliableTransfer => true;

	/// <summary>
	///   Returns a value indicating if the transport supports multicast communication
	/// </summary>
	public bool SupportsMulticastTransfer => false;

	/// <summary>
	///   Returns a value indicating if the transport supports pooled connections
	/// </summary>
	public bool SupportsPooledConnections => true;

	protected PipelinedClientTransportBase(int port)
	{
		_port = port;
	}

	/// <summary>
	///   Creates a new connection to a server
	/// </summary>
	/// <param name="endpointInfo">The endpoint to connect to</param>
	/// <param name="queryTimeout">The query timeout in milliseconds</param>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A connection to the specified server or null, if the connection could not be established</returns>
	public async Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
	{
		if (endpointInfo.IsMulticast)
			throw new NotSupportedException("Multicast is not supported on pipelined transports");

		Task<PipelinedClientConnection?>? connectTask;
		lock (_pool)
		{
			_pool.TryGetValue(endpointInfo.DestinationAddress, out connectTask);
		}

		if (connectTask == null)
		{
			connectTask = CreateConnectTask(endpointInfo, queryTimeout);

			lock (_pool)
			{
				if (!_pool.TryAdd(endpointInfo.DestinationAddress, connectTask))
				{
					connectTask = _pool[endpointInfo.DestinationAddress];
				}
			}
		}

		var con = await connectTask.WaitAsync(token);
		if (con == null || !con.IsAlive)
		{
			lock (_pool)
			{
				if (_pool.TryGetValue(endpointInfo.DestinationAddress, out var poolTask) && connectTask == poolTask)
					_pool.Remove(endpointInfo.DestinationAddress);
			}
		}

		return con;
	}

	private async Task<PipelinedClientConnection?> CreateConnectTask(DnsClientEndpointInfo endpointInfo, int queryTimeout)
	{
		var connection = await ConnectInternalAsync(endpointInfo, queryTimeout, CancellationToken.None);
		return connection == null ? null : new PipelinedClientConnection(this, connection, endpointInfo.DestinationAddress);
	}

	protected abstract Task<IPipelineableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token);

	/// <summary>
	///   Gets connection from the pool
	/// </summary>
	/// <param name="endpointInfo">The endpoint of the connection</param>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
	public async Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
	{
		Task<PipelinedClientConnection?>? connectTask;

		lock (_pool)
		{
			if (_pool.TryGetValue(endpointInfo.DestinationAddress, out connectTask)
			    && connectTask.IsCompleted
			    && (connectTask.Result == null || !connectTask.Result.IsAlive))
			{
				try
				{
					_pool.Remove(endpointInfo.DestinationAddress);
					if (connectTask.Result != null)
#pragma warning disable CA2016
#pragma warning disable IDE0079
#pragma warning disable CS4014
						// ReSharper disable once MethodSupportsCancellation
						Task.Run(() => connectTask.Result.MarkFaulty());
#pragma warning restore CS4014
#pragma warning restore IDE0079
#pragma warning restore CA2016
				}
				catch
				{
					// ignored
				}

				return null;
			}
		}

		if (connectTask == null)
			return null;

		return await connectTask.WaitAsync(token);
	}

	private void RemoveFromPool(PipelinedClientConnection connection)
	{
		lock (_pool)
		{
			if (_pool.TryGetValue(connection.DestinationAddress, out var connTask) && connTask.Result == connection)
			{
				_pool.Remove(connection.DestinationAddress);
			}
		}
	}

	public void Dispose()
	{
		lock (_pool)
		{
			foreach (var conTask in _pool.Values)
			{
				conTask.ContinueWith(c => c.Result?.MarkFaulty());
			}

			_pool.Clear();
		}
	}

	private class PipelinedClientConnection : IClientConnection
	{
		private readonly PipelinedClientTransportBase _transport;
		private readonly IPipelineableClientConnection _connection;
		internal IPAddress DestinationAddress { get; }

		private readonly Dictionary<DnsMessageIdentification, TaskCompletionSource<DnsReceivedRawPackage?>> _receivers = new();
		private CancellationTokenSource _globalReceiveCts = new();

		private readonly TaskIdleCompletionSource _idleTcs;

		public PipelinedClientConnection(PipelinedClientTransportBase transport, IPipelineableClientConnection connection, IPAddress destinationAddress)
		{
			_transport = transport;
			_connection = connection;
			DestinationAddress = destinationAddress;
			_idleTcs = new TaskIdleCompletionSource(TimeSpan.FromMilliseconds(100));
			_idleTcs.Task.ContinueWith((_) =>
			{
				MarkFaulty();
			});
		}

		public IClientTransport Transport => _transport;

		public bool IsAlive => _connection.IsAlive;

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = new())
		{
			lock (_connection)
			{
				_idleTcs.Pause();
				return _connection.SendAsync(package, token);
			}
		}

		private async Task ReceiveTaskProcInternal()
		{
			var isDone = false;

			_idleTcs.Pause();

			while (!isDone)
			{
				var package = await _connection.ReceiveAsync(_globalReceiveCts.Token);

				if (package == null)
				{
					lock (_receivers)
					{
						foreach (var kvp in _receivers)
						{
							kvp.Value.SetResult(null);
						}

						_receivers.Clear();
						return;
					}
				}
				else
				{
					TaskCompletionSource<DnsReceivedRawPackage?>? tcs;

					lock (_receivers)
					{
						_receivers.Remove(package.MessageIdentification, out tcs);

						if (_receivers.Count == 0)
						{
							isDone = true;
							_idleTcs.Start();
						}
					}

					tcs?.SetResult(package);
				}
			}
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
		{
			var tcs = new TaskCompletionSource<DnsReceivedRawPackage?>(TaskCreationOptions.RunContinuationsAsynchronously);

			var startReceiver = false;

			lock (_receivers)
			{
				_idleTcs.Pause();
				_receivers.Add(identification, tcs);

				if (_receivers.Count == 1)
				{
					_globalReceiveCts = new CancellationTokenSource();
					startReceiver = true;
				}
			}

			if (startReceiver)
				Task.Run(ReceiveTaskProcInternal).ConfigureAwait(false);

			if (token.CanBeCanceled)
				token.Register(CancelReceiveAsync, Tuple.Create(identification, tcs));

			return tcs.Task;
		}

		private void CancelReceiveAsync(object? state, CancellationToken token)
		{
			var casted = (Tuple<DnsMessageIdentification, TaskCompletionSource<DnsReceivedRawPackage?>>) state!;

			TaskCompletionSource<DnsReceivedRawPackage?>? tcs;

			lock (_receivers)
			{
				// Remove the from _receivers list, but ensure that there is no collision of the identifier
				if (_receivers.TryGetValue(casted.Item1, out tcs))
				{
					if (tcs == casted.Item2)
					{
						_receivers.Remove(casted.Item1, out tcs);
					}
				}

				if (_receivers.Count == 0)
					_globalReceiveCts.Cancel();
			}

			tcs?.TrySetCanceled();
		}

		public void RestartIdleTimeout(TimeSpan? timeout)
		{
			if (!timeout.HasValue)
				return;

			_idleTcs.SetIdleTimeout(TimeSpan.Zero);

			_connection.RestartIdleTimeout(timeout);
		}

		public bool IsFaulty => _connection.IsFaulty;

		public void MarkFaulty()
		{
			_transport.RemoveFromPool(this);
			_connection.MarkFaulty();
			_idleTcs.TryDispose();
			_connection.TryDispose();
		}

		public void Dispose()
		{
			// Do nothing as the DnsClient does Dispose the connection after each request
		}
	}
}