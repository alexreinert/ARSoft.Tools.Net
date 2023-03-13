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

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   Interface of a connection used by a server
/// </summary>
public interface IServerConnection : IDisposable
{
	/// <summary>
	///   The corresponding transport
	/// </summary>
	IServerTransport Transport { get; }

	/// <summary>
	///   Receives a new package of the client
	/// </summary>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A raw package sent by the client</returns>
	Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default);

	/// <summary>
	///   Sends a raw package to the client
	/// </summary>
	/// <param name="package">The package, which should be sent to the client</param>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>true, of the package could be sent to the client; otherwise, false</returns>
	Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default);

	/// <summary>
	///   The remote endpoint of the connection
	/// </summary>
	IPEndPoint RemoteEndPoint { get; }

	/// <summary>
	///   The local endpoint of the connection
	/// </summary>
	IPEndPoint LocalEndPoint { get; }

	/// <summary>
	///   A value indicating if data could be read from the client
	/// </summary>
	bool CanRead { get; }
}