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
	///   Endpoint info of a connection from a client to a server
	/// </summary>
	public class DnsClientEndpointInfo
	{
		/// <summary>
		///   Returns a value indicating if multicast communication is used
		/// </summary>
		public bool IsMulticast { get; }

		/// <summary>
		///   The remote IP address
		/// </summary>
		public IPAddress DestinationAddress { get; }

		/// <summary>
		///   The local IP address
		/// </summary>
		public IPAddress LocalAddress { get; }

		/// <summary>
		///   Creates a new instance of the DnsClientEndpointInfo class
		///   ///
		/// </summary>
		/// <param name="isMulticast">A value indicating if multicast communication is used</param>
		/// <param name="destinationAddress">The remote IP</param>
		/// <param name="localAddress">The local IP</param>
		public DnsClientEndpointInfo(bool isMulticast, IPAddress destinationAddress, IPAddress localAddress)
		{
			IsMulticast = isMulticast;
			DestinationAddress = destinationAddress;
			LocalAddress = localAddress;
		}
	}
}