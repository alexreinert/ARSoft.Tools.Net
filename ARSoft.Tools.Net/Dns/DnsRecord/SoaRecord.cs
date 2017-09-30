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
	public class SoaRecord : DnsRecordBase
	{
		public string MasterName { get; private set; }
		public string ResponsibleName { get; private set; }
		public int SerialNumber { get; private set; }
		public int RefreshInterval { get; private set; }
		public int RetryInterval { get; private set; }
		public int ExpireInterval { get; private set; }
		public int NegativeCachingTTL { get; private set; }

		internal SoaRecord() {}

		public SoaRecord(string name, int timeToLive, string masterName, string responsibleName, int serialNumber, int refreshInterval, int retryInterval, int expireInterval, int negativeCachingTTL)
			: base(name, RecordType.Soa, RecordClass.INet, timeToLive)
		{
			MasterName = masterName ?? String.Empty;
			ResponsibleName = responsibleName ?? String.Empty;
			SerialNumber = serialNumber;
			RefreshInterval = refreshInterval;
			RetryInterval = retryInterval;
			ExpireInterval = expireInterval;
			NegativeCachingTTL = negativeCachingTTL;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			MasterName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
			ResponsibleName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);

			SerialNumber = DnsMessageBase.ParseInt(resultData, ref startPosition);
			RefreshInterval = DnsMessageBase.ParseInt(resultData, ref startPosition);
			RetryInterval = DnsMessageBase.ParseInt(resultData, ref startPosition);
			ExpireInterval = DnsMessageBase.ParseInt(resultData, ref startPosition);
			NegativeCachingTTL = DnsMessageBase.ParseInt(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + MasterName + " " + ResponsibleName + " (" + SerialNumber + " " + RefreshInterval + " " + RetryInterval + " " + ExpireInterval + " " + NegativeCachingTTL + ")";
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return MasterName.Length + ResponsibleName.Length + 24; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, MasterName, true, domainNames);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, ResponsibleName, true, domainNames);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, SerialNumber);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, RefreshInterval);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, RetryInterval);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, ExpireInterval);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, NegativeCachingTTL);
		}
	}
}