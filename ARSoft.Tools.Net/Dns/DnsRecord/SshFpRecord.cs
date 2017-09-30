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
	public class SshFpRecord : DnsRecordBase
	{
		public enum SshFpAlgorithm : byte
		{
			None = 0,
			Rsa = 1, // RFC4255
			Dsa = 2, // RFC4255
		}

		public enum SshFpFingerPrintType : byte
		{
			None = 0,
			Sha1 = 1, // RFC4255
		}

		public SshFpAlgorithm Algorithm { get; private set; }
		public SshFpFingerPrintType FingerPrintType { get; private set; }
		public byte[] FingerPrint { get; private set; }

		internal SshFpRecord() {}

		public SshFpRecord(string name, int timeToLive, SshFpAlgorithm algorithm, SshFpFingerPrintType fingerPrintType, byte[] fingerPrint)
			: base(name, RecordType.SshFp, RecordClass.INet, timeToLive)
		{
			Algorithm = algorithm;
			FingerPrintType = fingerPrintType;
			FingerPrint = fingerPrint ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			Algorithm = (SshFpAlgorithm) resultData[currentPosition++];
			FingerPrintType = (SshFpFingerPrintType) resultData[currentPosition++];
			FingerPrint = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length - 2);
		}

		internal override string RecordDataToString()
		{
			return (byte) Algorithm
			       + " " + (byte) FingerPrintType
			       + " " + FingerPrint.ToBase16String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 2 + FingerPrint.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			messageData[currentPosition++] = (byte) Algorithm;
			messageData[currentPosition++] = (byte) FingerPrintType;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, FingerPrint);
		}
	}
}