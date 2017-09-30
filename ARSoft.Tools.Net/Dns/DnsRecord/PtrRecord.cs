using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class PtrRecord : DnsRecordBase
	{
		public string PointerDomainName { get; private set; }

		internal PtrRecord() { }

		public PtrRecord(string name, int timeToLive, string pointerDomainName)
			: base(name, RecordType.Ptr, RecordClass.INet, timeToLive)
		{
			PointerDomainName = pointerDomainName ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			PointerDomainName = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + PointerDomainName;
		}

		protected override int MaximumRecordDataLength
		{
			get { return PointerDomainName.Length + 2; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, PointerDomainName, true, domainNames);
		}
	}
}
