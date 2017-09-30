using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class CNameRecord : DnsRecordBase
	{
		public string CanonicalName { get; private set; }

		internal CNameRecord() { }

		public CNameRecord(string name, int timeToLive, string canonicalName)
			: base(name, RecordType.CName, RecordClass.INet, timeToLive)
		{
			CanonicalName = canonicalName ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			CanonicalName = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + CanonicalName;
		}

		protected override int MaximumRecordDataLength
		{
			get { return CanonicalName.Length + 2; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, CanonicalName, true, domainNames);
		}
	}
}
