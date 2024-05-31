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

using System;
using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Event arguments of <see cref="DnsServer.QueryReceived" /> event.
	/// </summary>
	public class QueryReceivedEventArgs : EventArgs
	{
		/// <summary>
		///   Original query, which the client provided
		/// </summary>
		public DnsMessageBase Query { get; private set; }

		/// <summary>
		///   Protocol used by the client
		/// </summary>
		[Obsolete("Use property TransportProtocol instead")]
		public ProtocolType ProtocolType => TransportProtocol.ToProtocolType();

		/// <summary>
		///   Protocol used by the client
		/// </summary>
		public TransportProtocol TransportProtocol { get; private set; }

		/// <summary>
		///   Remote endpoint of the client
		/// </summary>
		public IPEndPoint RemoteEndpoint { get; private set; }

		/// <summary>
		///   The response, which should be sent to the client
		/// </summary>
		public DnsMessageBase? Response { get; set; }

		internal QueryReceivedEventArgs(DnsMessageBase query, TransportProtocol transportProtocol, IPEndPoint remoteEndpoint)
		{
			Query = query;
			TransportProtocol = transportProtocol;
			RemoteEndpoint = remoteEndpoint;
		}
	}
}