using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class DnsRecordBase : DnsMessageEntryBase
	{
		public int TimeToLive { get; internal set; }

		internal DnsRecordBase() { }

		public DnsRecordBase(string name, RecordType recordType, RecordClass recordClass, int timeToLive)
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

				default:
					return new UnknownRecord();
			}
		}

		#region Sending data
		internal override sealed int MaximumLength
		{
			get
			{
				return Name.Length + 12 + MaximumRecordDataLength;
			}
		}

		internal override sealed void Encode(byte[] messageData, ref  int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, ref currentPosition, Name, true, domainNames);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)RecordType);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)RecordClass);
			DnsMessage.EncodeInt(messageData, ref currentPosition, TimeToLive);

			int recordPosition = currentPosition + 2;
			EncodeRecordData(messageData, ref recordPosition, domainNames);

			DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)(recordPosition - currentPosition - 2));
			currentPosition = recordPosition;
		}

		protected abstract int MaximumRecordDataLength { get; }

		protected abstract void EncodeRecordData(byte[] messageData, ref  int currentPosition, Dictionary<string, ushort> domainNames);
		#endregion
	}
}
