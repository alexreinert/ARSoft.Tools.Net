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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Cookie Option</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/draft-ietf-dnsop-cookies">draft-ietf-dnsop-cookies</see>
	///   </para>
	/// </summary>
	public class CookieOption : EDnsOptionBase
	{
		private byte[] _clientCookie;

		/// <summary>
		///   Client cookie
		/// </summary>
		public byte[] ClientCookie
		{
			get { return _clientCookie; }
			private set
			{
				if ((value == null) || (value.Length != 8))
					throw new ArgumentException("Client cookie must contain 8 bytes");
				_clientCookie = value;
			}
		}

		/// <summary>
		///   Server cookie
		/// </summary>
		public byte[] ServerCookie { get; private set; }

		/// <summary>
		///   Creates a new instance of the ClientCookie class
		/// </summary>
		public CookieOption()
			: base(EDnsOptionType.Cookie) {}

		/// <summary>
		///   Creates a new instance of the ClientCookie class
		/// </summary>
		/// <param name="clientCookie">The client cookie</param>
		/// <param name="serverCookie">The server cookie</param>
		public CookieOption(byte[] clientCookie, byte[] serverCookie = null)
			: this()
		{
			ClientCookie = clientCookie;
			ServerCookie = serverCookie ?? new byte[] { };
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			ClientCookie = DnsMessageBase.ParseByteData(resultData, ref startPosition, 8);
			ServerCookie = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 8);
		}

		internal override ushort DataLength => (ushort) (8 + ServerCookie.Length);

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, ClientCookie);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, ServerCookie);
		}
	}
}