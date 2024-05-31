#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Interface of a connection initiated by a client
	/// </summary>
	public interface IClientConnection : IDisposable
	{
		/// <summary>
		///   The corresponding transport
		/// </summary>
		IClientTransport Transport { get; }

		/// <summary>
		///   Sends as package to the server
		/// </summary>
		/// <param name="package">Package to be sent</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>true, if the package could be sent; otherwise, false</returns>
		Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default);

		/// <summary>
		///   Receives a package by the server
		/// </summary>
		/// <param name="identification">The identification of the message, that should be received</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>The package received by the server</returns>
		Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default);

		/// <summary>
		///   Restarts the idle timeout
		/// </summary>
		/// <param name="timeout">New idle timeout or null, if only the timer should be restarted</param>
		void RestartIdleTimeout(TimeSpan? timeout);

		/// <summary>
		///   Return a value indicating, if the connection is faulty.
		/// </summary>
		bool IsFaulty { get; }

		/// <summary>
		///   Marks the connection as faulty.
		/// </summary>
		void MarkFaulty();
	}
}