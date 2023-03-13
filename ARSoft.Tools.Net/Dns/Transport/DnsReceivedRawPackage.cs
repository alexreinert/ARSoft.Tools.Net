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
	///   A wrapper around the buffer of a received raw DNS package byte buffer
	///   The first two bytes are reserved for the length header
	/// </summary>
	public class DnsReceivedRawPackage : DnsRawPackage
	{
		/// <summary>
		///   Gets the local endpoint, where the package was received
		/// </summary>
		public IPEndPoint LocalEndpoint { get; }

		/// <summary>
		///   Gets the remote endpoint, where the package originates from
		/// </summary>
		public IPEndPoint RemoteEndpoint { get; }

		/// <summary>
		///   Creates a new instance of the DnsReceivedRawPackage class
		/// </summary>
		/// <param name="buffer"> Raw data of the DNS package including the length header</param>
		/// <param name="remoteEndpoint"> The remote endpoint, where the package was originates from </param>
		/// <param name="localEndpoint"> The local endpoint, where the package was received </param>
		public DnsReceivedRawPackage(byte[] buffer, IPEndPoint remoteEndpoint, IPEndPoint localEndpoint)
			: base(buffer)
		{
			RemoteEndpoint = remoteEndpoint;
			LocalEndpoint = localEndpoint;
		}
	}
}