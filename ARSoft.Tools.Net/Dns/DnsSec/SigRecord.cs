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
	public class SigRecord : DnsRecordBase
	{
		public RecordType TypeCovered { get; private set; }
		public DnsSecAlgorithm Algorithm { get; private set; }
		public byte Labels { get; private set; }
		public int OriginalTimeToLive { get; private set; }
		public DateTime SignatureExpiration { get; private set; }
		public DateTime SignatureInception { get; private set; }
		public ushort KeyTag { get; private set; }
		public string SignersName { get; private set; }
		public byte[] Signature { get; private set; }

		internal SigRecord() {}

		public SigRecord(string name, RecordClass recordClass, int timeToLive, RecordType typeCovered, DnsSecAlgorithm algorithm, byte labels, int originalTimeToLive, DateTime signatureExpiration, DateTime signatureInception, ushort keyTag, string signersName, byte[] signature)
			: base(name, RecordType.Sig, recordClass, timeToLive)
		{
			TypeCovered = typeCovered;
			Algorithm = algorithm;
			Labels = labels;
			OriginalTimeToLive = originalTimeToLive;
			SignatureExpiration = signatureExpiration;
			SignatureInception = signatureInception;
			KeyTag = keyTag;
			SignersName = signersName ?? String.Empty;
			Signature = signature ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			int currentPosition = startPosition;

			TypeCovered = (RecordType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Algorithm = (DnsSecAlgorithm) resultData[currentPosition++];
			Labels = resultData[currentPosition++];
			OriginalTimeToLive = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			SignatureExpiration = ParseDateTime(resultData, ref currentPosition);
			SignatureInception = ParseDateTime(resultData, ref currentPosition);
			KeyTag = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			SignersName = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
			Signature = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length + startPosition - currentPosition);
		}

		internal override string RecordDataToString()
		{
			return ToString(TypeCovered)
			       + " " + (byte) Algorithm
			       + " " + Labels
			       + " " + OriginalTimeToLive
			       + " " + SignatureExpiration.ToString("yyyyMMddHHmmss")
			       + " " + SignatureInception.ToString("yyyyMMddHHmmss")
			       + " " + KeyTag
			       + " " + SignersName
			       + " " + Signature.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 20 + SignersName.Length + Signature.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) TypeCovered);
			messageData[currentPosition++] = (byte) Algorithm;
			messageData[currentPosition++] = Labels;
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, OriginalTimeToLive);
			EncodeDateTime(messageData, ref currentPosition, SignatureExpiration);
			EncodeDateTime(messageData, ref currentPosition, SignatureInception);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, KeyTag);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, SignersName, false, null);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Signature);
		}

		internal static void EncodeDateTime(byte[] buffer, ref int currentPosition, DateTime value)
		{
			int timeStamp = (int) (value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
			DnsMessageBase.EncodeInt(buffer, ref currentPosition, timeStamp);
		}

		private static DateTime ParseDateTime(byte[] buffer, ref int currentPosition)
		{
			int timeStamp = DnsMessageBase.ParseInt(buffer, ref currentPosition);
			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp).ToLocalTime();
		}
	}
}