using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace ARSoft.Tools.Net.Dns
{
	public class ARecord : DnsRecordBase
	{
		public IPAddress Address { get; private set; }

		internal ARecord() { }

		public ARecord(string name, int timeToLive, IPAddress address)
			: base(name, RecordType.A, RecordClass.INet, timeToLive)
		{
			Address = address;
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			byte[] data = new byte[4];
			Buffer.BlockCopy(resultData, startPosition, data, 0, 4);
			Address = new IPAddress(data);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Address.ToString();
		}

		protected override int MaximumRecordDataLength
		{
			get { return 4; }
		}

		protected override void EncodeRecordData(byte[] messageData, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			Buffer.BlockCopy(Address.GetAddressBytes(), 0, messageData, currentPosition, 4);
			currentPosition += 4;
		}
	}
}
