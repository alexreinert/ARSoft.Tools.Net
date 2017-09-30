using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class SoaRecord : DnsRecordBase
	{
		public string MasterName { get; private set; }
		public string ResponsibleName { get; private set; }
		public int SerialNumber { get; private set; }
		public int RefreshInterval { get; private set; }
		public int RetryInterval { get; private set; }
		public int ExpireInterval { get; private set; }
		public int NegativeCachingTTL { get; private set; }

		internal SoaRecord() { }

		public SoaRecord(string name, int timeToLive, string masterName, string responsibleName, int serialNumber, int refreshInterval, int retryInterval, int expireInterval, int negativeCachingTTL)
			: base(name, RecordType.Soa, RecordClass.INet, timeToLive)
		{
			MasterName = masterName ?? String.Empty;
			ResponsibleName = responsibleName ?? String.Empty;
			SerialNumber = serialNumber;
			RefreshInterval = refreshInterval;
			RetryInterval = retryInterval;
			ExpireInterval = expireInterval;
			NegativeCachingTTL = negativeCachingTTL;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			MasterName = DnsMessage.ParseDomainName(resultData, ref startPosition);
			ResponsibleName = DnsMessage.ParseDomainName(resultData, ref startPosition);

			SerialNumber = DnsMessage.ParseInt(resultData, ref startPosition);
			RefreshInterval = DnsMessage.ParseInt(resultData, ref startPosition);
			RetryInterval = DnsMessage.ParseInt(resultData, ref startPosition);
			ExpireInterval = DnsMessage.ParseInt(resultData, ref startPosition);
			NegativeCachingTTL = DnsMessage.ParseInt(resultData, ref startPosition);
		}

		public override string ToString()
		{
			return base.ToString() + " " + MasterName + " " + ResponsibleName + " (" + SerialNumber + " " + RefreshInterval + " " + RetryInterval + " " + ExpireInterval + " " + NegativeCachingTTL + ")";
		}

		protected override int MaximumRecordDataLength
		{
			get { return MasterName.Length + ResponsibleName.Length + 24; }
		}

		protected override void EncodeRecordData(byte[] messageData, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeDomainName(messageData, ref currentPosition, MasterName, true, domainNames);
			DnsMessage.EncodeDomainName(messageData, ref currentPosition, ResponsibleName, true, domainNames);
			DnsMessage.EncodeInt(messageData, ref currentPosition, SerialNumber);
			DnsMessage.EncodeInt(messageData, ref currentPosition, RefreshInterval);
			DnsMessage.EncodeInt(messageData, ref currentPosition, RetryInterval);
			DnsMessage.EncodeInt(messageData, ref currentPosition, ExpireInterval);
			DnsMessage.EncodeInt(messageData, ref currentPosition, NegativeCachingTTL);
		}
	}
}
