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
	public class KeyRecord : KeyRecordBase
	{
		public byte[] PublicKey { get; private set; }

		internal KeyRecord() {}

		public KeyRecord(string name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, DnsSecAlgorithm algorithm, byte[] publicKey)
			: base(name, recordClass, timeToLive, flags, protocol, algorithm)
		{
			PublicKey = publicKey ?? new byte[] { };
		}

		protected override void ParsePublicKey(byte[] resultData, int startPosition, int length)
		{
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		protected override string PublicKeyToString()
		{
			return PublicKey.ToBase64String();
		}

		protected override int MaximumPublicKeyLength
		{
			get { return PublicKey.Length; }
		}

		protected override void EncodePublicKey(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}