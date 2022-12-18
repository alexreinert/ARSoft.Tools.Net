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
	///   <para>Name server ID option</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc5001.html">RFC 5001</a>.
	///   </para>
	/// </summary>
	public class NsIdOption : EDnsOptionBase
	{
		/// <summary>
		///   Binary data of the payload
		/// </summary>
		public byte[] Payload { get; private set; }

		internal NsIdOption(IList<byte> resultData, int startPosition, int length)
			: base(EDnsOptionType.NsId)
		{
			Payload = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		/// <summary>
		///   Creates a new instance of the NsIdOption class
		/// </summary>
		/// <param name="payload">Binary data of the payload</param>
		public NsIdOption(byte[] payload)
			: base(EDnsOptionType.NsId)
		{
			Payload = payload;
		}

		internal override ushort DataLength => (ushort) (Payload?.Length ?? 0);

		internal override void EncodeData(IList<byte> messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Payload);
		}
	}
}