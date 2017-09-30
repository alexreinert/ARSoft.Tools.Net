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
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Sender Policy Framework</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4408">RFC 4408</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc7208">RFC 7208</see>
	///   </para>
	/// </summary>
	[Obsolete]
	public class SpfRecord : TextRecordBase
	{
		internal SpfRecord() {}

		/// <summary>
		///   Creates a new instance of the SpfRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="textData"> Text data of the record </param>
		public SpfRecord(DomainName name, int timeToLive, string textData)
			: base(name, RecordType.Spf, timeToLive, textData) {}

		/// <summary>
		///   Creates a new instance of the SpfRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="textParts"> All parts of the text data </param>
		public SpfRecord(DomainName name, int timeToLive, IEnumerable<string> textParts)
			: base(name, RecordType.Spf, timeToLive, textParts) {}
	}
}