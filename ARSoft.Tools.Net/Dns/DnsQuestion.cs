using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class DnsQuestion : DnsMessageEntryBase
	{
		public DnsQuestion(string name, RecordType recordType, RecordClass recordClass)
		{
			Name = name ?? String.Empty;
			RecordType = recordType;
			RecordClass = recordClass;
		}

		internal DnsQuestion()
		{
		}

		internal override int MaximumLength
		{
			get { return Name.Length + 6; }
		}

		internal override void Encode(byte[] messageData, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, ref currentPosition, Name, true, domainNames);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)RecordType);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)RecordClass);
		}
	}
}
