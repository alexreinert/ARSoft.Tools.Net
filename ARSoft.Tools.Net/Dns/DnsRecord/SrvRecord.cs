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
	public class SrvRecord : DnsRecordBase
	{
		public ushort Priority { get; private set; }
		public ushort Weight { get; private set; }
		public ushort Port { get; private set; }
		public string Target { get; private set; }

		internal SrvRecord() {}

		public SrvRecord(string name, int timeToLive, ushort priority, ushort weight, ushort port, string target)
			: base(name, RecordType.Srv, RecordClass.INet, timeToLive)
		{
			Priority = priority;
			Weight = weight;
			Port = port;
			Target = target ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Priority = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Weight = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Port = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Target = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Priority
			       + " " + Weight
			       + " " + Port
			       + " " + Target;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return Target.Length + 8; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Priority);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Weight);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Port);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Target, false, domainNames);
		}
	}
}