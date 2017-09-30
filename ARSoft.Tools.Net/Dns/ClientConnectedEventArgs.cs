#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
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
	///   Event arguments of <see cref="DnsServer.ClientConnected" /> event.
	/// </summary>
	public class ClientConnectedEventArgs : EventArgs
	{
		/// <summary>
		///   Protocol used by the client
		/// </summary>
		public ProtocolType ProtocolType { get; private set; }

		/// <summary>
		///   Remote endpoint of the client
		/// </summary>
		public IPEndPoint RemoteEndpoint { get; private set; }

		/// <summary>
		///   If true, the client connection will be refused
		/// </summary>
		public bool RefuseConnect { get; set; }

		internal ClientConnectedEventArgs(ProtocolType protocolType, IPEndPoint remoteEndpoint)
		{
			ProtocolType = protocolType;
			RemoteEndpoint = remoteEndpoint;
		}
	}
}