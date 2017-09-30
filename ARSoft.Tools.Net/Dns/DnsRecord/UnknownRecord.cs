using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class UnknownRecord : DnsRecordBase
	{
		public byte[] RecordData { get; private set; }

		internal UnknownRecord() { }

		public UnknownRecord(string name, RecordType recordType, RecordClass recordClass, int timeToLive, byte[] recordData)
			: base(name, recordType, recordClass, timeToLive)
		{
			RecordData = recordData ?? new byte[] { };
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			RecordData = new byte[length];
			Buffer.BlockCopy(resultData, startPosition, RecordData, 0, length);
		}

		public override string ToString()
		{
			return base.ToString() + " " + Encoding.ASCII.GetString(RecordData);
		}

		protected override int MaximumRecordDataLength
		{
			get { return RecordData.Length; }
		}

		protected override void EncodeRecordData(byte[] messageData, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			if (RecordData.Length != 0)
			{
				Buffer.BlockCopy(RecordData, 0, messageData, currentPosition, RecordData.Length);
				currentPosition += RecordData.Length;
			}
		}
	}
}
