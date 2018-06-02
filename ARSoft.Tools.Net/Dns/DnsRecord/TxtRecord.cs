﻿#region Copyright and License
// Copyright 2010..2017 Alexander Reinert
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

using System.Collections.Generic;

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///   <para>Text strings</para>
    ///   <para>
    ///     Defined in
    ///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
    ///   </para>
    /// </summary>
    public class TxtRecord : TextRecordBase
	{
		internal TxtRecord() {}

		/// <summary>
		///   Creates a new instance of the TxtRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="textData"> Text data </param>
		public TxtRecord(DomainName name, int timeToLive, string textData)
			: base(name, RecordType.Txt, timeToLive, textData) {}

		/// <summary>
		///   Creates a new instance of the TxtRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="textParts"> All parts of the text data </param>
		public TxtRecord(DomainName name, int timeToLive, IEnumerable<string> textParts)
			: base(name, RecordType.Txt, timeToLive, textParts) {}
	}
}