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

using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   Protocol of a transport
/// </summary>
public enum TransportProtocol
{
	/// <summary>
	///   UDP
	/// </summary>
	Udp,

	/// <summary>
	///   TCP
	/// </summary>
	Tcp,

	/// <summary>
	///   TLS
	/// </summary>
	Tls,

	/// <summary>
	///   HTTPS
	/// </summary>
	Https,

	/// <summary>
	///   DTLS
	/// </summary>
	DTls,

	/// <summary>
	///   Custom
	/// </summary>
	Custom
}

internal static class TransportProtocolHelper
{
	public static ProtocolType ToProtocolType(this TransportProtocol protocol)
	{
		switch (protocol)
		{
			case TransportProtocol.Udp:
			case TransportProtocol.DTls:
				return ProtocolType.Udp;

			case TransportProtocol.Tcp:
			case TransportProtocol.Tls:
			case TransportProtocol.Https:
				return ProtocolType.Tcp;

			default:
				return ProtocolType.Unknown;
		}
	}
}