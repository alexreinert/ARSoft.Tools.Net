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
	public class HInfoRecord : DnsRecordBase
	{
		public string Cpu { get; private set; }
		public string OperatingSystem { get; private set; }

		internal HInfoRecord() {}

		public HInfoRecord(string name, int timeToLive, string cpu, string operatingSystem)
			: base(name, RecordType.HInfo, RecordClass.INet, timeToLive)
		{
			Cpu = cpu ?? String.Empty;
			OperatingSystem = operatingSystem ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Cpu = DnsMessageBase.ParseText(resultData, ref startPosition);
			OperatingSystem = DnsMessageBase.ParseText(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return "\"" + Cpu + "\""
			       + " \"" + OperatingSystem + "\"";
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 2 + Cpu.Length + OperatingSystem.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeText(messageData, ref currentPosition, Cpu);
			DnsMessageBase.EncodeText(messageData, ref currentPosition, OperatingSystem);
		}
	}
}