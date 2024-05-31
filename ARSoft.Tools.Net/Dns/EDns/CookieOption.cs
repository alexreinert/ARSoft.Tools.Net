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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Cookie Option</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc7873.html">RFC 7873</a>.
	///   </para>
	/// </summary>
	public class CookieOption : EDnsOptionBase
	{
		/// <summary>
		///   Client cookie
		/// </summary>
		public byte[] ClientCookie { get; }

		/// <summary>
		///   Server cookie
		/// </summary>
		public byte[] ServerCookie { get; }

		internal CookieOption(IList<byte> resultData, int startPosition, int length)
			: base(EDnsOptionType.Cookie)
		{
			ClientCookie = DnsMessageBase.ParseByteData(resultData, ref startPosition, 8);
			ServerCookie = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 8);
		}

		/// <summary>
		///   Creates a new instance of the ClientCookie class
		/// </summary>
		/// <param name="clientCookie">The client cookie</param>
		/// <param name="serverCookie">The server cookie</param>
		public CookieOption(byte[] clientCookie, byte[]? serverCookie = null)
			: base(EDnsOptionType.Cookie)
		{
			if ((clientCookie == null) || (clientCookie.Length != 8))
				throw new ArgumentException("Client cookie must contain 8 bytes");

			ClientCookie = clientCookie;
			ServerCookie = serverCookie ?? new byte[] { };
		}

		internal override ushort DataLength => (ushort) (8 + ServerCookie.Length);

		internal override void EncodeData(IList<byte> messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, ClientCookie);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, ServerCookie);
		}
	}
}