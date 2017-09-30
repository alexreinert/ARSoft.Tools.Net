#region Copyright and License
// Copyright 2010 Alexander Reinert
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
	public class TSigRecord : DnsRecordBase
	{
		public TSigAlgorithm Algorithm { get; private set; }
		public DateTime TimeSigned { get; internal set; }
		public TimeSpan Fudge { get; private set; }
		public byte[] OriginalMac { get; internal set; }
		public ushort OriginalID { get; private set; }
		public ReturnCode Error { get; internal set; }
		public byte[] OtherData { get; internal set; }

		public byte[] KeyData { get; internal set; }
		public ReturnCode ValidationResult { get; internal set; }

		internal TSigRecord() {}

		public TSigRecord(string name, TSigAlgorithm algorithm, DateTime timeSigned, TimeSpan fudge, ushort originalID, ReturnCode error, byte[] otherData, byte[] keyData)
			: base(name, RecordType.TSig, RecordClass.Any, 0)
		{
			Algorithm = algorithm;
			TimeSigned = timeSigned;
			Fudge = fudge;
			OriginalMac = new byte[] { };
			OriginalID = originalID;
			Error = error;
			OtherData = otherData ?? new byte[] { };
			KeyData = keyData;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			Algorithm = TSigAlgorithmHelper.GetAlgorithmByName(DnsMessageBase.ParseDomainName(resultData, ref startPosition));
			TimeSigned = ParseDateTime(resultData, ref startPosition);
			Fudge = TimeSpan.FromSeconds(DnsMessageBase.ParseUShort(resultData, ref startPosition));
			int macSize = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			OriginalMac = DnsMessageBase.ParseByteData(resultData, ref startPosition, macSize);
			OriginalID = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Error = (ReturnCode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			int otherDataSize = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			OtherData = DnsMessageBase.ParseByteData(resultData, ref startPosition, otherDataSize);
		}

		public override string ToString()
		{
			return base.ToString()
			       + " " + TSigAlgorithmHelper.GetDomainName(Algorithm)
			       + " " + (int) (TimeSigned - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
			       + " " + (ushort) Fudge.TotalSeconds
			       + " " + OriginalMac.Length
			       + " " + Convert.ToBase64String(OriginalMac)
			       + " " + OriginalID
			       + " " + EnumHelper<ReturnCode>.ToString(Error)
			       + " " + OtherData.Length
			       + " " + Convert.ToBase64String(OtherData);
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return TSigAlgorithmHelper.GetDomainName(Algorithm).Length + 18 + TSigAlgorithmHelper.GetHashSize(Algorithm) + OtherData.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, TSigAlgorithmHelper.GetDomainName(Algorithm), false, domainNames);
			EncodeDateTime(messageData, ref currentPosition, TimeSigned);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Fudge.TotalSeconds);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) OriginalMac.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, OriginalMac);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, OriginalID);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Error);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) OtherData.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, OtherData);
		}

		internal static void EncodeDateTime(byte[] buffer, ref int currentPosition, DateTime value)
		{
			long timeStamp = (long) (value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition] = (byte) ((timeStamp >> 40) & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 32) & 0xff);
				buffer[++currentPosition] = (byte) (timeStamp >> 24 & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 16) & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 8) & 0xff);
				buffer[++currentPosition] = (byte) (timeStamp & 0xff);
			}
			else
			{
				buffer[currentPosition] = (byte) (timeStamp & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 8) & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 16) & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 24) & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 32) & 0xff);
				buffer[++currentPosition] = (byte) ((timeStamp >> 40) & 0xff);
			}
			currentPosition++;
		}

		private static DateTime ParseDateTime(byte[] buffer, ref int currentPosition)
		{
			long timeStamp;

			if (BitConverter.IsLittleEndian)
			{
				timeStamp = ((buffer[currentPosition] << 40) | (buffer[++currentPosition] << 32) | buffer[++currentPosition] << 24 | (buffer[++currentPosition] << 16) | (buffer[++currentPosition] << 8) | buffer[++currentPosition]);
			}
			else
			{
				timeStamp = (buffer[currentPosition] | (buffer[++currentPosition] << 8) | (buffer[++currentPosition] << 16) | (buffer[++currentPosition] << 24) | (buffer[++currentPosition] << 32) | (buffer[++currentPosition] << 40));
			}

			currentPosition++;

			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp).ToLocalTime();
		}
	}
}