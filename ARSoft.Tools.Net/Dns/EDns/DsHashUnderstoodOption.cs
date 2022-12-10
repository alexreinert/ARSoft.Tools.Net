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
	///   <para>DS Hash Understood option</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc6975.html">RFC 6975</a>.
	///   </para>
	/// </summary>
	public class DsHashUnderstoodOption : EDnsOptionBase
	{
		/// <summary>
		///   List of Digests
		/// </summary>
		public List<DnsSecDigestType> Digests { get; private set; }

		internal DsHashUnderstoodOption(byte[] resultData, int startPosition, int length)
			: base(EDnsOptionType.DsHashUnderstood)
		{
			Digests = new List<DnsSecDigestType>(length);
			for (int i = 0; i < length; i++)
			{
				Digests.Add((DnsSecDigestType) resultData[startPosition++]);
			}
		}

		/// <summary>
		///   Creates a new instance of the DsHashUnderstoodOption class
		/// </summary>
		/// <param name="digests">The list of digests</param>
		public DsHashUnderstoodOption(params DnsSecDigestType[] digests)
			: base(EDnsOptionType.DsHashUnderstood)
		{
			Digests = digests.ToList();
		}

		internal override ushort DataLength => (ushort) (Digests?.Count ?? 0);

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			foreach (var algorithm in Digests)
			{
				messageData[currentPosition++] = (byte) algorithm;
			}
		}
	}
}