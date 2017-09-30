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
	public class PxRecord : DnsRecordBase
	{
		public ushort Preference { get; private set; }
		public string Map822 { get; private set; }
		public string MapX400 { get; private set; }

		internal PxRecord() {}

		public PxRecord(string name, int timeToLive, ushort preference, string map822, string mapX400)
			: base(name, RecordType.Px, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			Map822 = map822 ?? String.Empty;
			MapX400 = mapX400 ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Map822 = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
			MapX400 = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Preference
			       + " " + Map822
			       + " " + MapX400;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 6 + Map822.Length + MapX400.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Map822, false, domainNames);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, MapX400, false, domainNames);
		}
	}
}