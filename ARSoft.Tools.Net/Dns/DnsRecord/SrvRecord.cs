using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class SrvRecord : DnsRecordBase
	{
		public ushort Priority { get; private set; }
		public ushort Weight { get; private set; }
		public ushort Port { get; private set; }
		public string Target { get; private set; }

		internal SrvRecord() { }

		public SrvRecord(string name, int timeToLive, ushort priority, ushort weight, ushort port, string target)
			: base(name, RecordType.Srv, RecordClass.INet, timeToLive)
		{
			Priority = priority;
			Weight = weight;
			Port = port;
			Target = target ?? String.Empty;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			Priority = DnsMessage.ParseUShort(resultData, ref startPosition);
			Weight = DnsMessage.ParseUShort(resultData, ref startPosition);
			Port = DnsMessage.ParseUShort(resultData, ref startPosition);
			Target = DnsMessage.ParseDomainName(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Priority + " " + Weight + " " + Port + " " + Target;
		}

		protected override int MaximumRecordDataLength
		{
			get { return Target.Length + 8; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeUShort(messageData, ref currentPosition, Priority);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, Weight);
			DnsMessage.EncodeUShort(messageData, ref currentPosition, Port);
			DnsMessage.EncodeDomainName(messageData, offset, ref currentPosition, Target, false, domainNames);
		}
	}
}
