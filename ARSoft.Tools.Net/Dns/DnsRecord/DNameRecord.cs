using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class DNameRecord : DnsRecordBase
	{
		public string Target { get; private set; }

		internal DNameRecord() { }

		public DNameRecord(string name, int timeToLive, string target)
			: base(name, RecordType.DName, RecordClass.INet, timeToLive)
		{
			Target = target ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			Target = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Target;
		}

		protected override int MaximumRecordDataLength
		{
			get { return Target.Length + 2; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, Target, false, domainNames);
		}
	}
}
