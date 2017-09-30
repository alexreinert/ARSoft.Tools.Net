#region Copyright and License
// Copyright 2010..11 Alexander Reinert
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
	public class DlvRecord : DnsRecordBase
	{
		public ushort KeyTag { get; private set; }
		public DnsSecAlgorithm Algorithm { get; private set; }
		public DnsSecDigestType DigestType { get; private set; }
		public byte[] Digest { get; private set; }

		internal DlvRecord() {}

		public DlvRecord(string name, RecordClass recordClass, int timeToLive, ushort keyTag, DnsSecAlgorithm algorithm, DnsSecDigestType digestType, byte[] digest)
			: base(name, RecordType.Dlv, recordClass, timeToLive)
		{
			KeyTag = keyTag;
			Algorithm = algorithm;
			DigestType = digestType;
			Digest = digest ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			KeyTag = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			DigestType = (DnsSecDigestType) resultData[startPosition++];
			Digest = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 4);
		}

		internal override string RecordDataToString()
		{
			return KeyTag
			       + " " + (byte) Algorithm
			       + " " + (byte) DigestType
			       + " " + Digest.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 4 + Digest.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, KeyTag);
			messageData[currentPosition++] = (byte) Algorithm;
			messageData[currentPosition++] = (byte) DigestType;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Digest);
		}
	}
}