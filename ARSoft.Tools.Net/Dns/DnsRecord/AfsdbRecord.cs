using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class AfsdbRecord : DnsRecordBase
	{
		public enum AfsSubType : ushort
		{
			Afs = 1,
			Dce = 2,
		}

		public AfsSubType SubType { get; private set; }
		public string Hostname { get; private set; }

		internal AfsdbRecord() { }

		public AfsdbRecord(string name, int timeToLive, AfsSubType subType, string hostname)
			: base(name, RecordType.Mx, RecordClass.INet, timeToLive)
		{
			SubType = subType;
			Hostname = hostname ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			SubType = (AfsSubType)DnsMessage.ParseUShort(resultData, ref startPosition);
			Hostname = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + SubType + " " + Hostname;
		}

		protected override int MaximumRecordDataLength
		{
			get { return Hostname.Length + 4; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)SubType);
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, Hostname, false, domainNames);
		}
	}
}
