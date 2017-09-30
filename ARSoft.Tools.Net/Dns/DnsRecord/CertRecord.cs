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
	public class CertRecord : DnsRecordBase
	{
		public enum CertType : ushort
		{
			None = 0, // RFC4398
			Pkix = 1, // RFC4398
			Spki = 2, // RFC4398
			Pgp = 3, // RFC4398
			IPkix = 4, // RFC4398
			ISpki = 5, // RFC4398
			IPgp = 6, // RFC4398
			Acpkix = 7, // RFC4398
			IAcpkix = 8, // RFC4398
			Uri = 253, // RFC4398
			Oid = 254, // RFC4398
		}

		public CertType Type { get; private set; }
		public ushort KeyTag { get; private set; }
		public DnsSecAlgorithm Algorithm { get; private set; }
		public byte[] Certificate { get; private set; }

		internal CertRecord() {}

		public CertRecord(string name, int timeToLive, CertType type, ushort keyTag, DnsSecAlgorithm algorithm, byte[] certificate)
			: base(name, RecordType.Cert, RecordClass.INet, timeToLive)
		{
			Type = type;
			KeyTag = keyTag;
			Algorithm = algorithm;
			Certificate = certificate ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Type = (CertType) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			KeyTag = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			Certificate = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 5);
		}

		internal override string RecordDataToString()
		{
			return (ushort) Type
			       + " " + KeyTag
			       + " " + (byte) Algorithm
			       + " " + Certificate.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 5 + Certificate.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Type);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, KeyTag);
			messageData[currentPosition++] = (byte) Algorithm;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Certificate);
		}
	}
}