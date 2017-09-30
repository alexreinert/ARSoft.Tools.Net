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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class DnsRecordBase : DnsMessageEntryBase
	{
		internal int StartPosition { get; set; }
		internal ushort RecordDataLength { get; set; }

		public int TimeToLive { get; internal set; }

		internal DnsRecordBase() {}

		protected DnsRecordBase(string name, RecordType recordType, RecordClass recordClass, int timeToLive)
		{
			Name = name ?? String.Empty;
			RecordType = recordType;
			RecordClass = recordClass;
			TimeToLive = timeToLive;
		}

		internal abstract void ParseAnswer(byte[] resultData, int startPosition, int length);

		public override string ToString()
		{
			return Name + " " + RecordType + " " + RecordClass + " " + TimeToLive;
		}

		internal static DnsRecordBase Create(RecordType type)
		{
			switch (type)
			{
				case RecordType.A:
					return new ARecord();
				case RecordType.Ns:
					return new NsRecord();
				case RecordType.CName:
					return new CNameRecord();
				case RecordType.Soa:
					return new SoaRecord();
				case RecordType.Ptr:
					return new PtrRecord();
				case RecordType.Mx:
					return new MxRecord();
				case RecordType.Txt:
					return new TxtRecord();
				case RecordType.Afsdb:
					return new AfsdbRecord();
				case RecordType.Aaaa:
					return new AaaaRecord();
				case RecordType.Srv:
					return new SrvRecord();
				case RecordType.Naptr:
					return new NaptrRecord();
				case RecordType.DName:
					return new DNameRecord();
				case RecordType.Spf:
					return new SpfRecord();

				case RecordType.Opt:
					return new OptRecord();

				case RecordType.TSig:
					return new TSigRecord();

				default:
					return new UnknownRecord();
			}
		}

		#region Sending data
		internal override sealed int MaximumLength
		{
			get { return Name.Length + 12 + MaximumRecordDataLength; }
		}

		internal override sealed void Encode(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Name, true, domainNames);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordType);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordClass);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, TimeToLive);

			int recordPosition = currentPosition + 2;
			EncodeRecordData(messageData, offset, ref recordPosition, domainNames);

			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) (recordPosition - currentPosition - 2));
			currentPosition = recordPosition;
		}

		protected internal abstract int MaximumRecordDataLength { get; }

		protected internal abstract void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames);
		#endregion
	}
}