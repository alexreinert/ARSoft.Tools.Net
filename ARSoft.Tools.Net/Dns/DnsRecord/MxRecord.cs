using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class MxRecord : DnsRecordBase
	{
		public ushort Preference { get; private set; }
		public string ExchangeDomainName { get; private set; }

		internal MxRecord() { }

		public MxRecord(string name, int timeToLive, ushort preference, string exchangeDomainName)
			: base(name, RecordType.Mx, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			ExchangeDomainName = exchangeDomainName ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			Preference = DnsMessage.ParseUShort(resultData, ref startPosition);
			ExchangeDomainName = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Preference + " " + ExchangeDomainName;
		}

		protected override int MaximumRecordDataLength
		{
			get { return ExchangeDomainName.Length + 4; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, ExchangeDomainName, true, domainNames);
		}
	}
}
