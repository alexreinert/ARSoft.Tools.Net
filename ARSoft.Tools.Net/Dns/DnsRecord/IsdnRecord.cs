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
	public class IsdnRecord : DnsRecordBase
	{
		public string IsdnAddress { get; private set; }
		public string SubAddress { get; private set; }

		internal IsdnRecord() {}

		public IsdnRecord(string name, int timeToLive, string isdnAddress)
			: this(name, timeToLive, isdnAddress, String.Empty) {}

		public IsdnRecord(string name, int timeToLive, string isdnAddress, string subAddress)
			: base(name, RecordType.Isdn, RecordClass.INet, timeToLive)
		{
			IsdnAddress = isdnAddress ?? String.Empty;
			SubAddress = subAddress ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			IsdnAddress = DnsMessageBase.ParseText(resultData, ref currentPosition);
			SubAddress = (currentPosition < endPosition) ? DnsMessageBase.ParseText(resultData, ref currentPosition) : String.Empty;
		}

		internal override string RecordDataToString()
		{
			return IsdnAddress
			       + (String.IsNullOrEmpty(SubAddress) ? String.Empty : " " + SubAddress);
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 2 + IsdnAddress.Length + SubAddress.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeText(messageData, ref currentPosition, IsdnAddress);
			DnsMessageBase.EncodeText(messageData, ref currentPosition, SubAddress);
		}
	}
}