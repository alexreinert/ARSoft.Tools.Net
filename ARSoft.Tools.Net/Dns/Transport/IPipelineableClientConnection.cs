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
///   Interface of a pooled connection initiated by a client
/// </summary>
public interface IPipelineableClientConnection : IClientConnection
{
	/// <summary>
	///   Returns a value indicating if the connection is still alive
	/// </summary>
	bool IsAlive { get; }

	/// <summary>
	///   Receives a package by the server
	/// </summary>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>The package received by the server</returns>
	Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default);
}