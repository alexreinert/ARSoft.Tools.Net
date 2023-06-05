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

using System;
using System.Threading;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Interface of a transport used by a client
	/// </summary>
	public interface IClientTransport : IDisposable
	{
		/// <summary>
		///   The maximum allowed size of queries in bytes
		/// </summary>
		ushort MaximumAllowedQuerySize { get; }

		/// <summary>
		///   Returns a value indicating if the transport is reliable
		/// </summary>
		bool SupportsReliableTransfer { get; }

		/// <summary>
		///   Returns a value indicating if the transport supports multicast communication
		/// </summary>
		bool SupportsMulticastTransfer { get; }

		/// <summary>
		///   Returns a value indicating if the transport supports pooled connections
		/// </summary>
		bool SupportsPooledConnections { get; }

		/// <summary>
		///   Creates a new connection to a server
		/// </summary>
		/// <param name="endpointInfo">The endpoint to connect to</param>
		/// <param name="queryTimeout">The query timeout in milliseconds</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>A connection to the specified server or null, if the connection could not be established</returns>
		Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default);

		/// <summary>
		///   Gets connection from the pool
		/// </summary>
		/// <param name="endpointInfo">The endpoint of the connection</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
		Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default);
	}
}