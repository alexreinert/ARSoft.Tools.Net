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
	public class DiffieHellmanKeyRecord : KeyRecordBase
	{
		public byte[] Prime { get; private set; }
		public byte[] Generator { get; private set; }
		public byte[] PublicValue { get; private set; }

		internal DiffieHellmanKeyRecord() {}

		public DiffieHellmanKeyRecord(string name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, byte[] prime, byte[] generator, byte[] publicValue)
			: base(name, recordClass, timeToLive, flags, protocol, DnsSecAlgorithm.DiffieHellman)
		{
			Prime = prime ?? new byte[] { };
			Generator = generator ?? new byte[] { };
			PublicValue = publicValue ?? new byte[] { };
		}

		protected override void ParsePublicKey(byte[] resultData, int startPosition, int length)
		{
			int primeLength = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Prime = DnsMessageBase.ParseByteData(resultData, ref startPosition, primeLength);
			int generatorLength = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Generator = DnsMessageBase.ParseByteData(resultData, ref startPosition, generatorLength);
			int publicValueLength = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			PublicValue = DnsMessageBase.ParseByteData(resultData, ref startPosition, publicValueLength);
		}

		protected override string PublicKeyToString()
		{
			byte[] publicKey = new byte[MaximumPublicKeyLength];
			int currentPosition = 0;

			EncodePublicKey(publicKey, 0, ref currentPosition, null);

			return publicKey.ToBase64String();
		}

		protected override int MaximumPublicKeyLength
		{
			get { return 3 + Prime.Length + Generator.Length + PublicValue.Length; }
		}

		protected override void EncodePublicKey(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Prime.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Prime);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Generator.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Generator);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) PublicValue.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicValue);
		}
	}
}