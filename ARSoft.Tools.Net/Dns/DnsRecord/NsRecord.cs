using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class NsRecord : DnsRecordBase
	{
		public string NameServer { get; private set; }

		internal NsRecord() { }

		public NsRecord(string name, int timeToLive, string nameServer)
			: base(name, RecordType.Ns, RecordClass.INet, timeToLive)
		{
			NameServer = nameServer ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			NameServer = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + NameServer;
		}

		protected override int MaximumRecordDataLength
		{
			get { return NameServer.Length + 2; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, NameServer, true, domainNames);
		}
	}
}
