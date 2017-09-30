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
	public class NaptrRecord : DnsRecordBase
	{
		public ushort Order { get; private set; }
		public ushort Preference { get; private set; }
		public string Flags { get; private set; }
		public string Services { get; private set; }
		public string RegExp { get; private set; }
		public string Replacement { get; private set; }

		internal NaptrRecord() {}

		public NaptrRecord(string name, int timeToLive, ushort order, ushort preference, string flags, string services, string regExp, string replacement)
			: base(name, RecordType.Naptr, RecordClass.INet, timeToLive)
		{
			Order = order;
			Preference = preference;
			Flags = flags ?? String.Empty;
			Services = services ?? String.Empty;
			RegExp = regExp ?? String.Empty;
			Replacement = replacement ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Order = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Flags = DnsMessageBase.ParseText(resultData, ref startPosition);
			Services = DnsMessageBase.ParseText(resultData, ref startPosition);
			RegExp = DnsMessageBase.ParseText(resultData, ref startPosition);
			Replacement = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Order
			       + " " + Preference
			       + " \"" + Flags + "\""
			       + " \"" + Services + "\""
			       + " \"" + RegExp + "\""
			       + " \"" + Replacement + "\"";
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return Flags.Length + Services.Length + RegExp.Length + Replacement.Length + 13; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Order);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeText(messageData, ref currentPosition, Flags);
			DnsMessageBase.EncodeText(messageData, ref currentPosition, Services);
			DnsMessageBase.EncodeText(messageData, ref currentPosition, RegExp);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Replacement, false, domainNames);
		}
	}
}