using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class NaptrRecord : DnsRecordBase
	{
		public ushort Order { get; private set; }
		public ushort Preference { get; private set; }
		public string Flags { get; private set; }
		public string Services { get; private set; }
		public string RegExp { get; private set; }
		public string Replacement { get; private set; }

		internal NaptrRecord() { }

		public NaptrRecord(string name, int timeToLive, ushort order, ushort preference, string flags, string services, string regExp, string replacement)
			: base(name, RecordType.Naptr, RecordClass.INet, timeToLive)
		{
			Order = order;
			Preference = preference;
			Flags = flags ?? String.Empty;
			Services = services ?? String.Empty;
			RegExp = regExp ?? String.Empty;
			Replacement = replacement ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			Order = DnsMessage.ParseUShort(resultData, ref startPosition);
			Preference = DnsMessage.ParseUShort(resultData, ref startPosition);
			Flags = DnsMessage.ParseText(resultData, ref startPosition);
			Services = DnsMessage.ParseText(resultData, ref startPosition);
			RegExp = DnsMessage.ParseText(resultData, ref startPosition);
			Replacement = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Order + " " + Preference + " " + Flags + " " + Services + " " + RegExp + " " + Replacement;
		}

		protected override int MaximumRecordDataLength
		{
			get { return Flags.Length + Services.Length + RegExp.Length + Replacement.Length + 13; }
		}

		protected override void EncodeRecordData(byte[] messageData, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeUShort(messageData, ref currentPosition, Order);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessage.EncodeText(messageData, ref currentPosition, Flags);
			DnsMessage.EncodeText(messageData, ref currentPosition, Services);
			DnsMessage.EncodeText(messageData, ref currentPosition, RegExp);
			DnsMessage.EncodeDomainName(messageData, ref currentPosition, Replacement, false, domainNames);
		}
	}
}
