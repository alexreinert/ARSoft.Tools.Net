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
	public class NSec3Record : DnsRecordBase
	{
		public DnsSecAlgorithm HashAlgorithm { get; private set; }
		public byte Flags { get; private set; }
		public ushort Iterations { get; private set; }
		public byte[] Salt { get; private set; }
		public byte[] NextHashedOwnerName { get; private set; }
		public List<RecordType> Types { get; private set; }

		internal NSec3Record() {}

		public NSec3Record(string name, RecordClass recordClass, int timeToLive, DnsSecAlgorithm hashAlgorithm, byte flags, ushort iterations, byte[] salt, byte[] nextHashedOwnerName, List<RecordType> types)
			: base(name, RecordType.NSec3, recordClass, timeToLive)
		{
			HashAlgorithm = hashAlgorithm;
			Flags = flags;
			Iterations = iterations;
			Salt = salt ?? new byte[] { };
			NextHashedOwnerName = nextHashedOwnerName ?? new byte[] { };

			if ((types == null) || (types.Count == 0))
			{
				Types = new List<RecordType>();
			}
			else
			{
				Types = new List<RecordType>(types);
				types.Sort((left, right) => ((ushort) left).CompareTo((ushort) right));
			}
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			HashAlgorithm = (DnsSecAlgorithm) resultData[currentPosition++];
			Flags = resultData[currentPosition++];
			Iterations = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int saltLength = resultData[currentPosition++];
			Salt = DnsMessageBase.ParseByteData(resultData, ref currentPosition, saltLength);
			int hashLength = resultData[currentPosition++];
			NextHashedOwnerName = DnsMessageBase.ParseByteData(resultData, ref currentPosition, hashLength);
			Types = NSecRecord.ParseTypeBitMap(resultData, ref currentPosition, endPosition);
		}

		internal override string RecordDataToString()
		{
			return (byte) HashAlgorithm
			       + " " + Flags
			       + " " + Iterations
			       + " " + ((Salt.Length == 0) ? "-" : Salt.ToBase16String())
			       + " " + NextHashedOwnerName.ToBase32HexString()
			       + " " + String.Join(" ", Types.ConvertAll(ToString).ToArray());
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 6 + Salt.Length + NextHashedOwnerName.Length + NSecRecord.GetMaximumTypeBitmapLength(Types); }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			messageData[currentPosition++] = (byte) HashAlgorithm;
			messageData[currentPosition++] = Flags;
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Iterations);
			messageData[currentPosition++] = (byte) Salt.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Salt);
			messageData[currentPosition++] = (byte) NextHashedOwnerName.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, NextHashedOwnerName);
			NSecRecord.EncodeTypeBitmap(messageData, ref currentPosition, Types);
		}
	}
}