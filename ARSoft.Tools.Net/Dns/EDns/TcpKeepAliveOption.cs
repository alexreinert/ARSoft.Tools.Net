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

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>edns-tcp-keepalive EDNS0 Option</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc7828.html">RFC 7828</a>.
///   </para>
/// </summary>
public class TcpKeepAliveOption : EDnsOptionBase
{
	/// <summary>
	///   The timeout
	/// </summary>
	public TimeSpan? Timeout { get; }

	internal TcpKeepAliveOption(IList<byte> resultData, int startPosition, int length)
		: base(EDnsOptionType.TcpKeepAlive)
	{
		if (length == 2)
			Timeout = TimeSpan.FromMilliseconds(DnsMessageBase.ParseUShort(resultData, ref startPosition) * 100);
	}

	/// <summary>
	///   Creates a new instance of the TcpKeepAliveOption class
	/// </summary>
	/// <param name="timeout">The timeout or null, if the timeout should be omitted</param>
	public TcpKeepAliveOption(TimeSpan? timeout = null)
		: base(EDnsOptionType.TcpKeepAlive)
	{
		Timeout = timeout;
	}

	internal override ushort DataLength => (ushort) (Timeout.HasValue ? 2 : 0);

	internal override void EncodeData(IList<byte> messageData, ref int currentPosition)
	{
		if (Timeout.HasValue)
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) ((int) Timeout.Value.TotalMilliseconds / 100));
	}
}