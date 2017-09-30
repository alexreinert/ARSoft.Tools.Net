using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class TxtRecord : DnsRecordBase
	{
		public string TextData { get; protected set; }

		internal TxtRecord() { }

		public TxtRecord(string name, int timeToLive, string textData)
			: this(name, RecordType.Txt, RecordClass.INet, timeToLive, textData)
		{
		}

		public TxtRecord(string name, RecordType recordType, RecordClass recordClass, int timeToLive, string textData)
			: base(name, recordType, recordClass, timeToLive)
		{
			TextData = textData;
		}


		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			int endPosition = startPosition + length;

			TextData = String.Empty;
			while (startPosition < endPosition)
			{
				TextData += DnsMessage.ParseText(resultData, ref startPosition);
			}
		}

		public override string ToString()
		{
			return base.ToString() + " " + TextData;
		}

		protected override int MaximumRecordDataLength
		{
			get { return TextData.Length + (TextData.Length / 255) + (TextData.Length % 255 == 0 ? 0 : 1); }
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessage.EncodeText(messageData, ref currentPosition, TextData);
		}
	}
}
