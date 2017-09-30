using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class OptRecord : DnsRecordBase
	{
		/// <summary>
		/// Gets or set the sender's UDP payload size
		/// </summary>
		public ushort UpdPayloadSize
		{
			get { return (ushort)RecordClass; }
			set { RecordClass = (RecordClass)value; }
		}

		/// <summary>
		/// Gets or sets the high bits of return code (EXTENDED-RCODE)
		/// </summary>
		public ReturnCode ExtendedReturnCode
		{
			get
			{
				return (ReturnCode)((TimeToLive & 0xff000000) >> 20);
			}
			set
			{
				int clearedTtl = (TimeToLive & 0x00ffffff);
				TimeToLive = (clearedTtl | ((int)value << 20));
			}
		}

		/// <summary>
		/// Gets or set the EDNS version
		/// </summary>
		public byte Version
		{
			get
			{
				return (byte)((TimeToLive & 0x00ff0000) >> 16);
			}
			set
			{
				int clearedTtl = (int)((uint)TimeToLive & 0xff00ffff);
				TimeToLive = (int)(clearedTtl | (value << 16));
			}
		}

		/// <summary>
		/// Gets or sets the DNSSEC OK (DO) flag
		/// </summary>
		public bool IsDnsSecOk
		{
			get
			{
				return (TimeToLive & 0x8000) != 0;
			}
			set
			{
				if (value)
				{
					TimeToLive |= 0x8000;
				}
				else
				{
					TimeToLive ^= 0x8000;
				}
			}
		}

		/// <summary>
		/// Gets or set additional EDNS options
		/// </summary>
		public List<EDnsOptionBase> Options { get; set; }

		public OptRecord()
			: base(".", RecordType.Opt, unchecked((RecordClass)512), 0)
		{
		}

		internal override void ParseAnswer(byte[] resultData, int startPosition, int length)
		{
			int endPosition = startPosition + length;

			Options = new List<EDnsOptionBase>();
			while (startPosition < endPosition)
			{
				EDnsOptionType type = (EDnsOptionType)DnsMessage.ParseUShort(resultData, ref startPosition);
				ushort dataLength = DnsMessage.ParseUShort(resultData, ref startPosition);

				EDnsOptionBase option;

				switch (type)
				{
					case EDnsOptionType.NsId:
						option = new NsIdOption();
						break;

					default:
						option = new UnknownOption(type);
						break;
				}

				option.ParseData(resultData, startPosition, dataLength);
				Options.Add(option);
				startPosition += dataLength;
			}
		}

		public override string ToString()
		{
			string flags = IsDnsSecOk ? "DO" : "";
			return String.Format("; EDNS version: {0}; flags: {1}; udp: {2}", Version, flags, UpdPayloadSize);
		}

		protected override int MaximumRecordDataLength
		{
			get
			{
				if ((Options == null) || (Options.Count == 0))
				{
					return 0;
				}
				else
				{
					int res = 0;
					foreach (EDnsOptionBase option in Options)
					{
						res += option.DataLength + 4;
					}
					return res;
				}
			}
		}

		protected override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			if ((Options != null) && (Options.Count != 0))
			{
				foreach (EDnsOptionBase option in Options)
				{
					DnsMessage.EncodeUShort(messageData, ref currentPosition, (ushort)option.Type);
					DnsMessage.EncodeUShort(messageData, ref currentPosition, option.DataLength);
					option.EncodeData(messageData, ref currentPosition);
				}
			}
		}
	}
}
