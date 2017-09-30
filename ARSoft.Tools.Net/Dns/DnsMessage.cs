using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

namespace ARSoft.Tools.Net.Dns
{
	public class DnsMessage
	{
		#region Header
		public ushort TransactionID { get; set; }
		private ushort Flags;

		public bool IsQuery
		{
			get
			{
				return (Flags & (ushort)0x8000) == 0;
			}
			set
			{
				if (value)
				{
					Flags &= 0x7fff;
				}
				else
				{
					Flags |= 0x8000;
				}
			}
		}

		public OperationCode OperationCode
		{
			get
			{
				return (OperationCode)(Flags & (ushort)0x7800);
			}
			set
			{
				ushort clearedOp = (ushort)(Flags & (ushort)0x8700);
				Flags = (ushort)(clearedOp | (ushort)value);
			}
		}

		public bool IsAuthoritiveAnswer
		{
			get
			{
				return (Flags & (ushort)0x0400) != 0;
			}
			set
			{
				if (value)
				{
					Flags |= (ushort)0x0400;
				}
				else
				{
					Flags &= (ushort)0xfbff;
				}
			}
		}

		public bool IsTruncated
		{
			get
			{
				return (Flags & (ushort)0x0200) != 0;
			}
			set
			{
				if (value)
				{
					Flags |= (ushort)0x0200;
				}
				else
				{
					Flags &= (ushort)0xfdff;
				}
			}
		}

		public bool IsRecursionDesired
		{
			get
			{
				return (Flags & (ushort)0x0100) != 0;
			}
			set
			{
				if (value)
				{
					Flags |= (ushort)0x0100;
				}
				else
				{
					Flags &= (ushort)0xfeff;
				}
			}
		}

		public bool IsRecursionAllowed
		{
			get
			{
				return (Flags & (ushort)0x0080) != 0;
			}
			set
			{
				if (value)
				{
					Flags |= (ushort)0x0080;
				}
				else
				{
					Flags &= (ushort)0xff7f;
				}
			}
		}

		public bool IsAuthenticData
		{
			get
			{
				return (Flags & (ushort)0x0020) != 0;
			}
			set
			{
				if (value)
				{
					Flags |= (ushort)0x0020;
				}
				else
				{
					Flags &= (ushort)0xffdf;
				}
			}
		}

		public bool IsCheckingDisabled
		{
			get
			{
				return (Flags & (ushort)0x0010) != 0;
			}
			set
			{
				if (value)
				{
					Flags |= (ushort)0x0010;
				}
				else
				{
					Flags &= (ushort)0xffef;
				}
			}
		}
		
		public ReturnCode ReturnCode
		{
			get
			{
				return (ReturnCode)(Flags & (ushort)0x000f);
			}
			internal set
			{
				ushort clearedOp = (ushort)(Flags & (ushort)0xfff0);
				Flags = (ushort)(clearedOp | (ushort)value);
			}
		}
		#endregion

		public List<DnsQuestion> Questions { get; private set; }
		public List<DnsRecordBase> AnswerRecords { get; private set; }
		public List<DnsRecordBase> AuthorityRecords { get; private set; }
		public List<DnsRecordBase> AdditionalRecords { get; private set; }

		public DnsMessage()
		{
			Questions = new List<DnsQuestion>();
			AnswerRecords = new List<DnsRecordBase>();
			AuthorityRecords = new List<DnsRecordBase>();
			AdditionalRecords = new List<DnsRecordBase>();
		}

		#region Parsing
		internal void Parse(byte[] resultData)
		{
			int currentPosition = 0;

			TransactionID = DnsMessage.ParseUShort(resultData, ref currentPosition);
			Flags = DnsMessage.ParseUShort(resultData, ref currentPosition);

			int questionCount = DnsMessage.ParseUShort(resultData, ref currentPosition);
			int answerRecordCount = DnsMessage.ParseUShort(resultData, ref currentPosition);
			int authorityRecordCount = DnsMessage.ParseUShort(resultData, ref currentPosition);
			int additionalRecordCount = DnsMessage.ParseUShort(resultData, ref currentPosition);

			ParseQuestions(resultData, ref currentPosition, questionCount);
			ParseSection(resultData, ref currentPosition, AnswerRecords, answerRecordCount);
			ParseSection(resultData, ref currentPosition, AuthorityRecords, authorityRecordCount);
			ParseSection(resultData, ref currentPosition, AdditionalRecords, additionalRecordCount);
		}

		#region Methods for parsing answer
		private void ParseSection(byte[] resultData, ref int currentPositon, List<DnsRecordBase> sectionList, int recordCount)
		{
			for (int i = 0; i < recordCount; i++)
			{
				sectionList.Add(ParseRecord(resultData, ref currentPositon));
			}
		}

		private DnsRecordBase ParseRecord(byte[] resultData, ref int currentPosition)
		{
			string name = ParseDomainName(resultData, ref currentPosition);
			RecordType recordType = (RecordType)ParseUShort(resultData, ref currentPosition);

			DnsRecordBase record = DnsRecordBase.Create(recordType);
			record.Name = name;
			record.RecordType = recordType;
			record.RecordClass = (RecordClass)ParseUShort(resultData, ref currentPosition);
			record.TimeToLive = ParseInt(resultData, ref currentPosition);
			ushort recordDataLength = ParseUShort(resultData, ref currentPosition);

			record.ParseAnswer(resultData, currentPosition, recordDataLength);
			currentPosition += recordDataLength;

			return record;
		}

		private void ParseQuestions(byte[] resultData, ref int currentPosition, int recordCount)
		{
			for (int i = 0; i < recordCount; i++)
			{
				DnsQuestion question = new DnsQuestion();

				question.Name = ParseDomainName(resultData, ref currentPosition);
				question.RecordType = (RecordType)ParseUShort(resultData, ref currentPosition);
				question.RecordClass = (RecordClass)ParseUShort(resultData, ref currentPosition);

				Questions.Add(question);
			}
		}
		#endregion

		#region Helper methods for parsing records
		internal static string ParseText(byte[] resultData, ref int currentPosition)
		{
			int length = resultData[currentPosition];
			currentPosition++;

			string res = Encoding.ASCII.GetString(resultData, currentPosition, length);
			currentPosition += length;

			return res;
		}

		internal static string ParseDomainName(byte[] resultData, ref int currentPosition)
		{
			StringBuilder sb = new StringBuilder();

			ParseDomainName(resultData, ref currentPosition, sb);

			return (sb.Length == 0) ? String.Empty : sb.ToString(0, sb.Length - 1);
		}

		internal static ushort ParseUShort(byte[] resultData, ref int currentPosition)
		{
			ushort res;

			if (BitConverter.IsLittleEndian)
			{
				res = (ushort)((resultData[currentPosition] << 8) | resultData[++currentPosition]);
			}
			else
			{
				res = (ushort)(resultData[currentPosition] | (resultData[++currentPosition] << 8));
			}

			currentPosition++;

			return res;
		}

		internal static int ParseInt(byte[] resultData, ref int currentPosition)
		{
			int res;

			if (BitConverter.IsLittleEndian)
			{
				res = ((resultData[currentPosition] << 24) | (resultData[++currentPosition] << 16) | (resultData[++currentPosition] << 8) | resultData[++currentPosition]);
			}
			else
			{
				res = (resultData[currentPosition] | (resultData[++currentPosition] << 8) | (resultData[++currentPosition] << 16) | (resultData[++currentPosition] << 24));
			}

			currentPosition++;

			return res;
		}

		private static void ParseDomainName(byte[] resultData, ref int currentPosition, StringBuilder sb)
		{
			while (true)
			{
				byte currentByte = resultData[currentPosition];
				if (currentByte == 0)
				{
					// end of domain
					currentPosition++;
					return;
				}
				else if (currentByte >= 192)
				{
					// Pointer
					int pointer;
					if (BitConverter.IsLittleEndian)
					{
						pointer = (ushort)(((currentByte - 192) << 8) | resultData[++currentPosition]);
					}
					else
					{
						pointer = (ushort)((currentByte - 192) | (resultData[++currentPosition] << 8));
					}
					currentPosition++;

					ParseDomainName(resultData, ref pointer, sb);

					return;
				}
				else if (currentByte >= 64)
				{
					// EDNS label, not supported yet
				}
				else
				{
					// append additional text part
					sb.Append(ParseText(resultData, ref currentPosition));
					sb.Append(".");
				}
			}
		}
		#endregion
		#endregion

		#region Serializing
		internal int Encode(out byte[] messageData)
		{
			#region Get Message Length
			int length = 12;
			foreach (DnsQuestion question in Questions)
			{
				length += question.MaximumLength;
			}
			foreach (DnsRecordBase record in AnswerRecords)
			{
				length += record.MaximumLength;
			}
			foreach (DnsRecordBase record in AuthorityRecords)
			{
				length += record.MaximumLength;
			}
			foreach (DnsRecordBase record in AdditionalRecords)
			{
				length += record.MaximumLength;
			}
			#endregion

			messageData = new byte[length];
			int currentPosition = 0;

			Dictionary<string, ushort> domainNames = new Dictionary<string, ushort>();

			EncodeUShort(messageData, ref currentPosition, TransactionID);
			EncodeUShort(messageData, ref currentPosition, Flags);
			EncodeUShort(messageData, ref currentPosition, (ushort)Questions.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort)AnswerRecords.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort)AuthorityRecords.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort)AdditionalRecords.Count);

			foreach (DnsQuestion question in Questions)
			{
				question.Encode(messageData, ref currentPosition, domainNames);
			}
			foreach (DnsRecordBase record in AnswerRecords)
			{
				record.Encode(messageData, ref currentPosition, domainNames);
			}
			foreach (DnsRecordBase record in AuthorityRecords)
			{
				record.Encode(messageData, ref currentPosition, domainNames);
			}
			foreach (DnsRecordBase record in AdditionalRecords)
			{
				record.Encode(messageData, ref currentPosition, domainNames);
			}

			return currentPosition;
		}

		internal static void EncodeUShort(byte[] buffer, ref int currentPosition, ushort value)
		{
			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition] = (byte)((value >> 8) & 0xff);
				buffer[++currentPosition] = (byte)(value & 0xff);
			}
			else
			{
				buffer[currentPosition] = (byte)(value & 0xff);
				buffer[++currentPosition] = (byte)((value >> 8) & 0xff);
			}
			currentPosition++;
		}

		internal static void EncodeInt(byte[] buffer, ref int currentPosition, int value)
		{
			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition] = (byte)((value >> 24) & 0xff);
				buffer[++currentPosition] = (byte)((value >> 16) & 0xff);
				buffer[++currentPosition] = (byte)((value >> 8) & 0xff);
				buffer[++currentPosition] = (byte)(value & 0xff);
			}
			else
			{
				buffer[currentPosition] = (byte)(value & 0xff);
				buffer[++currentPosition] = (byte)((value >> 8) & 0xff);
				buffer[++currentPosition] = (byte)((value >> 16) & 0xff);
				buffer[++currentPosition] = (byte)((value >> 24) & 0xff);
			}
			currentPosition++;
		}

		internal static void EncodeDomainName(byte[] messageData, ref int currentPosition, string name, bool isCompressionAllowed, Dictionary<string, ushort> domainNames)
		{
			if (String.IsNullOrEmpty(name) || name == ".")
			{
				messageData[currentPosition] = 0;
				currentPosition++;
				return;
			}

			ushort pointer;
			if (isCompressionAllowed && domainNames.TryGetValue(name, out pointer))
			{
				EncodeUShort(messageData, ref currentPosition, pointer);
				return;
			}

			int labelLength = name.IndexOf('.');
			if (labelLength == -1)
				labelLength = name.Length;

			domainNames[name] = (ushort)(currentPosition | 0xc000);

			messageData[currentPosition] = (byte)labelLength;
			currentPosition++;
			Buffer.BlockCopy(Encoding.ASCII.GetBytes(name.ToCharArray(0, labelLength)), 0, messageData, currentPosition, labelLength);
			currentPosition += labelLength;

			if (labelLength == name.Length)
			{
				EncodeDomainName(messageData, ref currentPosition, ".", isCompressionAllowed, domainNames);
			}
			else
			{
				EncodeDomainName(messageData, ref currentPosition, name.Substring(labelLength + 1), isCompressionAllowed, domainNames);
			}
		}

		internal static void EncodeText(byte[] messageData, ref int currentPosition, string text)
		{
			byte[] textData = Encoding.ASCII.GetBytes(text.ToCharArray());

			for (int i = 0; i < textData.Length; i += 255)
			{
				int blockLength = Math.Min(255, (textData.Length - i));
				messageData[currentPosition] = (byte)blockLength;
				currentPosition++;

				Buffer.BlockCopy(textData, i, messageData, currentPosition, blockLength);
				currentPosition += blockLength;
			}
		}
		#endregion
	}
}
