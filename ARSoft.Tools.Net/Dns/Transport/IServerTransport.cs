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

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   Interface of a transport used by a client
/// </summary>
public interface IServerTransport : IDisposable
{
	/// <summary>
	///   The default allowed response size if no EDNS option is set.
	/// </summary>
	ushort DefaultAllowedResponseSize { get; }

	/// <summary>
	///   A value indicating, if the transport supports sending multiple response to a single query.
	/// </summary>
	bool SupportsMultipleResponses { get; }

	/// <summary>
	///   A value indicating, if truncated responses are allowed using this transport.
	/// </summary>
	bool AllowTruncatedResponses { get; }

	/// <summary>
	///   The transport protocol this transport is using
	/// </summary>
	TransportProtocol TransportProtocol { get; }

	/// <summary>
	///   Binds the transport to the network stack
	/// </summary>
	void Bind();

	/// <summary>
	///   Closes the transport
	/// </summary>
	void Close();

	/// <summary>
	///   Waits for a new connection and return the connection
	/// </summary>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A new connection to a client or null, if no connection could not be established</returns>
	Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default);
}