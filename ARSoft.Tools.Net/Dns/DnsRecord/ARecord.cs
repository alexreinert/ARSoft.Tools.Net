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
using System.Net;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class ARecord : DnsRecordBase
	{
		public IPAddress Address { get; private set; }

		internal ARecord() {}

		public ARecord(string name, int timeToLive, IPAddress address)
			: base(name, RecordType.A, RecordClass.INet, timeToLive)
		{
			Address = address;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			byte[] data = new byte[4];
			Buffer.BlockCopy(resultData, startPosition, data, 0, 4);
			Address = new IPAddress(data);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Address;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 4; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			Buffer.BlockCopy(Address.GetAddressBytes(), 0, messageData, currentPosition, 4);
			currentPosition += 4;
		}
	}
}