#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Expire EDNS Option</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc7314.html">RFC 7314</a>.
	///   </para>
	/// </summary>
	public class ExpireOption : EDnsOptionBase
	{
		/// <summary>
		///   The expiration of the SOA record in seconds. Should be null on queries.
		/// </summary>
		public int? SoaExpire { get; private set; }

		internal ExpireOption(IList<byte> resultData, int startPosition, int length)
			: base(EDnsOptionType.Expire)
		{
			if (length == 4)
				SoaExpire = DnsMessageBase.ParseInt(resultData, ref startPosition);
		}

		/// <summary>
		///   Creates a new instance of the ExpireOption class
		/// </summary>
		/// <param name="soaExpire">The expiration of the SOA record in seconds</param>
		public ExpireOption(int soaExpire)
			: base(EDnsOptionType.Expire)
		{
			SoaExpire = soaExpire;
		}

		internal override ushort DataLength => (ushort) (SoaExpire.HasValue ? 4 : 0);

		internal override void EncodeData(IList<byte> messageData, ref int currentPosition)
		{
			if (SoaExpire.HasValue)
				DnsMessageBase.EncodeInt(messageData, ref currentPosition, SoaExpire.Value);
		}
	}
}