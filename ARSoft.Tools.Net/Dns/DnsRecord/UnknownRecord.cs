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

namespace ARSoft.Tools.Net.Dns
{
    /// <summary>
    ///   Represent a dns record, which is not directly supported by this library
    /// </summary>
    public class UnknownRecord : DnsRecordBase
	{
		/// <summary>
		///   Binary data of the RDATA section of the record
		/// </summary>
		public byte[] RecordData { get; private set; }

		internal UnknownRecord() {}

		/// <summary>
		///   Creates a new instance of the UnknownRecord class
		/// </summary>
		/// <param name="name"> Domain name of the record </param>
		/// <param name="recordType"> Record type </param>
		/// <param name="recordClass"> Record class </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="recordData"> Binary data of the RDATA section of the record </param>
		public UnknownRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, byte[] recordData)
			: base(name, recordType, recordClass, timeToLive)
		{
			RecordData = recordData ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			RecordData = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			ParseUnknownRecordData(stringRepresentation);
		}

		internal override string RecordDataToString()
		{
			return @"\# " + (RecordData == null ? "0" : RecordData.Length + " " + RecordData.ToBase16String());
		}

		protected internal override int MaximumRecordDataLength => RecordData.Length;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, RecordData);
		}
	}
}