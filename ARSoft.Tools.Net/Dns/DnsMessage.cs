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
		/// <summary>
		/// Gets or sets the transaction identifier (ID) of the message
		/// </summary>
		public ushort TransactionID { get; set; }

		private ushort Flags;

		/// <summary>
		/// Gets or sets the query (QR) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the Operation Code (OPCODE)
		/// </summary>
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

		/// <summary>
		/// Gets or sets the autoritive answer (AA) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the truncated (TC) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the recursion desired (RD) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the recursion allowed (RA) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the authentic data (AD) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the checking disabled (CD) flag
		/// </summary>
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

		/// <summary>
		/// Gets or sets the return code (RCODE)
		/// </summary>
		public ReturnCode ReturnCode
		{
			get
			{
				ReturnCode rcode = (ReturnCode)(Flags & (ushort)0x000f);

				OptRecord ednsOptions = EDnsOptions;
				if (ednsOptions == null)
				{
					return rcode;
				}
				else
				{
					return (rcode | ednsOptions.ExtendedReturnCode);
				}
			}
			set
			{
				OptRecord ednsOptions = EDnsOptions;

				if ((ushort)value > 15)
				{
					if (ednsOptions == null)
					{
						throw new ArgumentOutOfRangeException("Only ReturnCodes greater than 15 allowed in edns messages");
					}
					else
					{
						ednsOptions.ExtendedReturnCode = value;
					}
				}
				else
				{
					if (ednsOptions != null)
					{
						ednsOptions.ExtendedReturnCode = 0;
					}
				}

				ushort clearedOp = (ushort)(Flags & (ushort)0xfff0);
				Flags = (ushort)(clearedOp | ((ushort)value & ((ushort)0x0f)));
			}
		}
		#endregion

		private List<DnsQuestion> _questions = new List<DnsQuestion>();
		/// <summary>
		/// Gets or sets the entries in the question section
		/// </summary>
		public List<DnsQuestion> Questions
		{
			get { return _questions; }
			set { _questions = (value ?? new List<DnsQuestion>()); }
		}

		private List<DnsRecordBase> _answerRecords = new List<DnsRecordBase>();
		/// <summary>
		/// Gets or sets the entries in the answer records section
		/// </summary>
		public List<DnsRecordBase> AnswerRecords
		{
			get { return _answerRecords; }
			set { _answerRecords = (value ?? new List<DnsRecordBase>()); }
		}

		private List<DnsRecordBase> _authorityRecords = new List<DnsRecordBase>();
		/// <summary>
		/// Gets or sets the entries in the authority records section
		/// </summary>
		public List<DnsRecordBase> AuthorityRecords
		{
			get { return _authorityRecords; }
			set { _authorityRecords = (value ?? new List<DnsRecordBase>()); }
		}

		private List<DnsRecordBase> _additionalRecords = new List<DnsRecordBase>();
		/// <summary>
		/// Gets or sets the entries in the additional records section
		/// </summary>
		public List<DnsRecordBase> AdditionalRecords
		{
			get { return _additionalRecords; }
			set { _additionalRecords = (value ?? new List<DnsRecordBase>()); }
		}

		#region EDNS
		/// <summary>
		/// Enables or disables EDNS
		/// </summary>
		public bool IsEDnsEnabled
		{
			get
			{
				if (AdditionalRecords != null)
				{
					return AdditionalRecords.Where(Record => (Record.RecordType == RecordType.Opt)).Count() != 0;
				}
				else
				{
					return false;
				}
			}
			set
			{
				if (value && !IsEDnsEnabled)
				{
					if (AdditionalRecords == null)
					{
						AdditionalRecords = new List<DnsRecordBase>();
					}
					AdditionalRecords.Add(new OptRecord());
				}
				else if (!value && IsEDnsEnabled)
				{
					AdditionalRecords.RemoveAll(Record => (Record.RecordType == RecordType.Opt));
				}
			}
		}

		/// <summary>
		/// Gets or set the OptRecord for the EDNS options
		/// </summary>
		public OptRecord EDnsOptions
		{
			get
			{
				if (AdditionalRecords != null)
				{
					return (OptRecord)AdditionalRecords.Find(Record => (Record.RecordType == RecordType.Opt));
				}
				else
				{
					return null;
				}
			}
			set
			{
				if (value == null)
				{
					IsEDnsEnabled = false;
				}
				else if (IsEDnsEnabled)
				{
					int pos = AdditionalRecords.FindIndex(Record => (Record.RecordType == RecordType.Opt));
					AdditionalRecords[0] = value;
				}
				else
				{
					if (AdditionalRecords == null)
					{
						AdditionalRecords = new List<DnsRecordBase>();
					}
					AdditionalRecords.Add(value);
				}
			}
		}

		/// <summary>
		/// Gets or sets the DNSSEC OK (DO) flag
		/// </summary>
		public bool IsDnsSecOk
		{
			get
			{
				OptRecord ednsOptions = EDnsOptions;
				if (ednsOptions == null)
				{
					return false;
				}
				else
				{
					return ednsOptions.IsDnsSecOk;
				}
			}
			set
			{
				OptRecord ednsOptions = EDnsOptions;
				if (ednsOptions == null)
				{
					if (value)
					{
						throw new ArgumentOutOfRangeException("Setting DO flag is allowed in edns messages only");
					}
				}
				else
				{
					ednsOptions.IsDnsSecOk = value;
				}
			}
		}
		#endregion

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
				else if (currentByte == 65)
				{
					// binary EDNS label
					int length = resultData[++currentPosition];
					if (length == 0)
						length = 256;

					sb.Append(@"\[x");
					string suffix = "/" + length + "]";

					do
					{
						currentByte = resultData[++currentPosition];
						if (length < 8)
						{
							currentByte &= (byte)(((byte)0xff) >> (8 - length));
						}

						sb.Append(currentByte.ToString("x2"));

						length = length - 8;
					} while (length > 0);

					sb.Append(suffix);
					currentPosition++;
				}
				else if (currentByte >= 64)
				{
					// undefined EDNS label
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
			return Encode(out messageData, false);
		}

		internal int Encode(out byte[] messageData, bool addLengthPrefix)
		{
			int offset = (addLengthPrefix ? 2 : 0);

			#region Get Message Length
			int maxLength = 12 + offset;
			foreach (DnsQuestion question in Questions)
			{
				maxLength += question.MaximumLength;
			}
			foreach (DnsRecordBase record in AnswerRecords)
			{
				maxLength += record.MaximumLength;
			}
			foreach (DnsRecordBase record in AuthorityRecords)
			{
				maxLength += record.MaximumLength;
			}
			foreach (DnsRecordBase record in AdditionalRecords)
			{
				maxLength += record.MaximumLength;
			}
			#endregion

			messageData = new byte[maxLength];
			int currentPosition = offset;

			Dictionary<string, ushort> domainNames = new Dictionary<string, ushort>();

			EncodeUShort(messageData, ref currentPosition, TransactionID);
			EncodeUShort(messageData, ref currentPosition, Flags);
			EncodeUShort(messageData, ref currentPosition, (ushort)Questions.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort)AnswerRecords.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort)AuthorityRecords.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort)AdditionalRecords.Count);

			foreach (DnsQuestion question in Questions)
			{
				question.Encode(messageData, offset, ref currentPosition, domainNames);
			}
			foreach (DnsRecordBase record in AnswerRecords)
			{
				record.Encode(messageData, offset, ref currentPosition, domainNames);
			}
			foreach (DnsRecordBase record in AuthorityRecords)
			{
				record.Encode(messageData, offset, ref currentPosition, domainNames);
			}
			foreach (DnsRecordBase record in AdditionalRecords)
			{
				record.Encode(messageData, offset, ref currentPosition, domainNames);
			}

			if (addLengthPrefix)
			{
				int tmp = 0;
				DnsMessage.EncodeUShort(messageData, ref tmp, (ushort)(currentPosition - offset));
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

		internal static void EncodeDomainName(byte[] messageData, int offset, ref int currentPosition, string name, bool isCompressionAllowed, Dictionary<string, ushort> domainNames)
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

			domainNames[name] = (ushort)((currentPosition | 0xc000) - offset);

			messageData[currentPosition] = (byte)labelLength;
			currentPosition++;
			Buffer.BlockCopy(Encoding.ASCII.GetBytes(name.ToCharArray(0, labelLength)), 0, messageData, currentPosition, labelLength);
			currentPosition += labelLength;

			if (labelLength == name.Length)
			{
				EncodeDomainName(messageData, offset, ref currentPosition, ".", isCompressionAllowed, domainNames);
			}
			else
			{
				EncodeDomainName(messageData, offset, ref currentPosition, name.Substring(labelLength + 1), isCompressionAllowed, domainNames);
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
