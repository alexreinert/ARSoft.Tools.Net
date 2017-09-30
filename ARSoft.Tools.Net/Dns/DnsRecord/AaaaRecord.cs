using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace ARSoft.Tools.Net.Dns
{
	public class AaaaRecord : DnsRecordBase
	{
		public IPAddress Address { get; private set; }

		internal AaaaRecord() { }

		public AaaaRecord(string name, int timeToLive, IPAddress address)
			: base(name, RecordType.Aaaa, RecordClass.INet, timeToLive)
		{
			Address = address;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			byte[] data = new byte[16];
			Buffer.BlockCopy(resultData, startPosition, data, 0, 16);
			Address = new IPAddress(data);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Address.ToString();
		}

		protected override int MaximumRecordDataLength
		{
			get { return 16; }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			Buffer.BlockCopy(Address.GetAddressBytes(), 0, messageData, currentPosition, 16);
			currentPosition += 16;
		}
	}
}
