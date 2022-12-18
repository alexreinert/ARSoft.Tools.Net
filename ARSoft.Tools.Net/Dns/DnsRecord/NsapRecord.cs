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
	///   <para>NSAP address, NSAP style A record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc1706.html">RFC 1706</a>
	///     and
	///     <a href="https://www.rfc-editor.org/rfc/rfc1348.html">RFC 1348</a>.
	///   </para>
	/// </summary>
	public class NsapRecord : DnsRecordBase
	{
		/// <summary>
		///   Binary encoded NSAP data
		/// </summary>
		public byte[] RecordData { get; private set; }

		internal NsapRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			RecordData = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length);
		}

		internal NsapRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 1)
				throw new FormatException();

			if (!stringRepresentation[0].StartsWith("0x", StringComparison.InvariantCultureIgnoreCase))
				throw new FormatException();

			RecordData = stringRepresentation[0].Substring(2).Replace(".", String.Empty).FromBase16String();
		}

		/// <summary>
		///   Creates a new instance of the NsapRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="recordData"> Binary encoded NSAP data </param>
		public NsapRecord(DomainName name, int timeToLive, byte[] recordData)
			: base(name, RecordType.Nsap, RecordClass.INet, timeToLive)
		{
			RecordData = recordData ?? new byte[] { };
		}

		internal override string RecordDataToString()
		{
			return "0x" + RecordData.ToBase16String();
		}

		protected internal override int MaximumRecordDataLength => RecordData.Length;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, RecordData);
		}
	}
}