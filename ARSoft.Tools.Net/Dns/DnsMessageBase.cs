#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ARSoft.Tools.Net.Dns.DynamicUpdate;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Base class for a dns answer
	/// </summary>
	public abstract class DnsMessageBase
	{
		protected ushort Flags;

		protected internal List<DnsQuestion> Questions = new List<DnsQuestion>();
		protected internal List<DnsRecordBase> AnswerRecords = new List<DnsRecordBase>();
		protected internal List<DnsRecordBase> AuthorityRecords = new List<DnsRecordBase>();

		private List<DnsRecordBase> _additionalRecords = new List<DnsRecordBase>();

		/// <summary>
		///   Gets or sets the entries in the additional records section
		/// </summary>
		public List<DnsRecordBase> AdditionalRecords
		{
			get { return _additionalRecords; }
			set { _additionalRecords = (value ?? new List<DnsRecordBase>()); }
		}

		internal abstract bool IsTcpUsingRequested { get; }
		internal abstract bool IsTcpResendingRequested { get; }
		internal abstract bool IsTcpNextMessageWaiting(bool isSubsequentResponseMessage);

		#region Header
		/// <summary>
		///   Gets or sets the transaction identifier (ID) of the message
		/// </summary>
		public ushort TransactionID { get; set; }

		/// <summary>
		///   Gets or sets the query (QR) flag
		/// </summary>
		public bool IsQuery
		{
			get { return (Flags & 0x8000) == 0; }
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
		///   Gets or sets the Operation Code (OPCODE)
		/// </summary>
		public OperationCode OperationCode
		{
			get { return (OperationCode) ((Flags & 0x7800) >> 11); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0x8700);
				Flags = (ushort) (clearedOp | (ushort) value << 11);
			}
		}

		/// <summary>
		///   Gets or sets the return code (RCODE)
		/// </summary>
		public ReturnCode ReturnCode
		{
			get
			{
				ReturnCode rcode = (ReturnCode) (Flags & 0x000f);

				OptRecord ednsOptions = EDnsOptions;
				if (ednsOptions == null)
				{
					return rcode;
				}
				else
				{
					// ReSharper disable once BitwiseOperatorOnEnumWithoutFlags
					return (rcode | ednsOptions.ExtendedReturnCode);
				}
			}
			set
			{
				OptRecord ednsOptions = EDnsOptions;

				if ((ushort) value > 15)
				{
					if (ednsOptions == null)
					{
						throw new ArgumentOutOfRangeException(nameof(value), "ReturnCodes greater than 15 only allowed in edns messages");
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

				ushort clearedOp = (ushort) (Flags & 0xfff0);
				Flags = (ushort) (clearedOp | ((ushort) value & 0x0f));
			}
		}
		#endregion

		#region EDNS
		/// <summary>
		///   Enables or disables EDNS
		/// </summary>
		public bool IsEDnsEnabled
		{
			get
			{
				if (_additionalRecords != null)
				{
					return _additionalRecords.Any(record => (record.RecordType == RecordType.Opt));
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
					if (_additionalRecords == null)
					{
						_additionalRecords = new List<DnsRecordBase>();
					}
					_additionalRecords.Add(new OptRecord());
				}
				else if (!value && IsEDnsEnabled)
				{
					_additionalRecords.RemoveAll(record => (record.RecordType == RecordType.Opt));
				}
			}
		}

		/// <summary>
		///   Gets or set the OptRecord for the EDNS options
		/// </summary>
		public OptRecord EDnsOptions
		{
			get { return (OptRecord) _additionalRecords?.Find(record => (record.RecordType == RecordType.Opt)); }
			set
			{
				if (value == null)
				{
					IsEDnsEnabled = false;
				}
				else if (IsEDnsEnabled)
				{
					int pos = _additionalRecords.FindIndex(record => (record.RecordType == RecordType.Opt));
					_additionalRecords[pos] = value;
				}
				else
				{
					if (_additionalRecords == null)
					{
						_additionalRecords = new List<DnsRecordBase>();
					}
					_additionalRecords.Add(value);
				}
			}
		}
		#endregion

		#region TSig
		/// <summary>
		///   Gets or set the TSigRecord for the tsig signed messages
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public TSigRecord TSigOptions { get; set; }

		internal static DnsMessageBase CreateByFlag(byte[] data, DnsServer.SelectTsigKey tsigKeySelector, byte[] originalMac)
		{
			int flagPosition = 2;
			ushort flags = ParseUShort(data, ref flagPosition);

			DnsMessageBase res;

			switch ((OperationCode) ((flags & 0x7800) >> 11))
			{
				case OperationCode.Update:
					res = new DnsUpdateMessage();
					break;

				default:
					res = new DnsMessage();
					break;
			}

			res.ParseInternal(data, tsigKeySelector, originalMac);

			return res;
		}

		internal static TMessage Parse<TMessage>(byte[] data)
			where TMessage : DnsMessageBase, new()
		{
			return Parse<TMessage>(data, null, null);
		}

		internal static TMessage Parse<TMessage>(byte[] data, DnsServer.SelectTsigKey tsigKeySelector, byte[] originalMac)
			where TMessage : DnsMessageBase, new()
		{
			TMessage result = new TMessage();
			result.ParseInternal(data, tsigKeySelector, originalMac);
			return result;
		}

		private void ParseInternal(byte[] data, DnsServer.SelectTsigKey tsigKeySelector, byte[] originalMac)
		{
			int currentPosition = 0;

			TransactionID = ParseUShort(data, ref currentPosition);
			Flags = ParseUShort(data, ref currentPosition);

			int questionCount = ParseUShort(data, ref currentPosition);
			int answerRecordCount = ParseUShort(data, ref currentPosition);
			int authorityRecordCount = ParseUShort(data, ref currentPosition);
			int additionalRecordCount = ParseUShort(data, ref currentPosition);

			ParseQuestions(data, ref currentPosition, questionCount);
			ParseSection(data, ref currentPosition, AnswerRecords, answerRecordCount);
			ParseSection(data, ref currentPosition, AuthorityRecords, authorityRecordCount);
			ParseSection(data, ref currentPosition, _additionalRecords, additionalRecordCount);

			if (_additionalRecords.Count > 0)
			{
				int tSigPos = _additionalRecords.FindIndex(record => (record.RecordType == RecordType.TSig));
				if (tSigPos == (_additionalRecords.Count - 1))
				{
					TSigOptions = (TSigRecord) _additionalRecords[tSigPos];

					_additionalRecords.RemoveAt(tSigPos);

					TSigOptions.ValidationResult = ValidateTSig(data, tsigKeySelector, originalMac);
				}
			}

			FinishParsing();
		}

		private ReturnCode ValidateTSig(byte[] resultData, DnsServer.SelectTsigKey tsigKeySelector, byte[] originalMac)
		{
			byte[] keyData;
			if ((TSigOptions.Algorithm == TSigAlgorithm.Unknown) || (tsigKeySelector == null) || ((keyData = tsigKeySelector(TSigOptions.Algorithm, TSigOptions.Name)) == null))
			{
				return ReturnCode.BadKey;
			}
			else if (((TSigOptions.TimeSigned - TSigOptions.Fudge) > DateTime.Now) || ((TSigOptions.TimeSigned + TSigOptions.Fudge) < DateTime.Now))
			{
				return ReturnCode.BadTime;
			}
			else if ((TSigOptions.Mac == null) || (TSigOptions.Mac.Length == 0))
			{
				return ReturnCode.BadSig;
			}
			else
			{
				TSigOptions.KeyData = keyData;

				// maxLength for the buffer to validate: Original (unsigned) dns message and encoded TSigOptions
				// because of compression of keyname, the size of the signed message can not be used
				int maxLength = TSigOptions.StartPosition + TSigOptions.MaximumLength;
				if (originalMac != null)
				{
					// add length of mac on responses. MacSize not neccessary, this field is allready included in the size of the tsig options
					maxLength += originalMac.Length;
				}

				byte[] validationBuffer = new byte[maxLength];

				int currentPosition = 0;

				// original mac if neccessary
				if ((originalMac != null) && (originalMac.Length > 0))
				{
					EncodeUShort(validationBuffer, ref currentPosition, (ushort) originalMac.Length);
					EncodeByteArray(validationBuffer, ref currentPosition, originalMac);
				}

				// original unsiged buffer
				Buffer.BlockCopy(resultData, 0, validationBuffer, currentPosition, TSigOptions.StartPosition);

				// update original transaction id and ar count in message
				EncodeUShort(validationBuffer, currentPosition, TSigOptions.OriginalID);
				EncodeUShort(validationBuffer, currentPosition + 10, (ushort) _additionalRecords.Count);
				currentPosition += TSigOptions.StartPosition;

				// TSig Variables
				EncodeDomainName(validationBuffer, 0, ref currentPosition, TSigOptions.Name, null, false);
				EncodeUShort(validationBuffer, ref currentPosition, (ushort) TSigOptions.RecordClass);
				EncodeInt(validationBuffer, ref currentPosition, (ushort) TSigOptions.TimeToLive);
				EncodeDomainName(validationBuffer, 0, ref currentPosition, TSigAlgorithmHelper.GetDomainName(TSigOptions.Algorithm), null, false);
				TSigRecord.EncodeDateTime(validationBuffer, ref currentPosition, TSigOptions.TimeSigned);
				EncodeUShort(validationBuffer, ref currentPosition, (ushort) TSigOptions.Fudge.TotalSeconds);
				EncodeUShort(validationBuffer, ref currentPosition, (ushort) TSigOptions.Error);
				EncodeUShort(validationBuffer, ref currentPosition, (ushort) TSigOptions.OtherData.Length);
				EncodeByteArray(validationBuffer, ref currentPosition, TSigOptions.OtherData);

				// Validate MAC
				KeyedHashAlgorithm hashAlgorithm = TSigAlgorithmHelper.GetHashAlgorithm(TSigOptions.Algorithm);
				hashAlgorithm.Key = keyData;
				return (hashAlgorithm.ComputeHash(validationBuffer, 0, currentPosition).SequenceEqual(TSigOptions.Mac)) ? ReturnCode.NoError : ReturnCode.BadSig;
			}
		}
		#endregion

		#region Parsing
		protected virtual void FinishParsing() {}

		#region Methods for parsing answer
		private static void ParseSection(byte[] resultData, ref int currentPosition, List<DnsRecordBase> sectionList, int recordCount)
		{
			for (int i = 0; i < recordCount; i++)
			{
				sectionList.Add(ParseRecord(resultData, ref currentPosition));
			}
		}

		private static DnsRecordBase ParseRecord(byte[] resultData, ref int currentPosition)
		{
			int startPosition = currentPosition;

			DomainName name = ParseDomainName(resultData, ref currentPosition);
			RecordType recordType = (RecordType) ParseUShort(resultData, ref currentPosition);
			DnsRecordBase record = DnsRecordBase.Create(recordType, resultData, currentPosition + 6);
			record.StartPosition = startPosition;
			record.Name = name;
			record.RecordType = recordType;
			record.RecordClass = (RecordClass) ParseUShort(resultData, ref currentPosition);
			record.TimeToLive = ParseInt(resultData, ref currentPosition);
			record.RecordDataLength = ParseUShort(resultData, ref currentPosition);

			if (record.RecordDataLength > 0)
			{
				record.ParseRecordData(resultData, currentPosition, record.RecordDataLength);
				currentPosition += record.RecordDataLength;
			}

			return record;
		}

		private void ParseQuestions(byte[] resultData, ref int currentPosition, int recordCount)
		{
			for (int i = 0; i < recordCount; i++)
			{
				DnsQuestion question = new DnsQuestion { Name = ParseDomainName(resultData, ref currentPosition), RecordType = (RecordType) ParseUShort(resultData, ref currentPosition), RecordClass = (RecordClass) ParseUShort(resultData, ref currentPosition) };

				Questions.Add(question);
			}
		}
		#endregion

		#region Helper methods for parsing records
		internal static string ParseText(byte[] resultData, ref int currentPosition)
		{
			int length = resultData[currentPosition++];
			return ParseText(resultData, ref currentPosition, length);
		}

		internal static string ParseText(byte[] resultData, ref int currentPosition, int length)
		{
			string res = Encoding.ASCII.GetString(resultData, currentPosition, length);
			currentPosition += length;

			return res;
		}

		internal static DomainName ParseDomainName(byte[] resultData, ref int currentPosition)
		{
			int firstLabelLength;
			DomainName res = ParseDomainName(resultData, currentPosition, out firstLabelLength);
			currentPosition += firstLabelLength;
			return res;
		}

		internal static ushort ParseUShort(byte[] resultData, ref int currentPosition)
		{
			ushort res;

			if (BitConverter.IsLittleEndian)
			{
				res = (ushort) ((resultData[currentPosition++] << 8) | resultData[currentPosition++]);
			}
			else
			{
				res = (ushort) (resultData[currentPosition++] | (resultData[currentPosition++] << 8));
			}

			return res;
		}

		internal static int ParseInt(byte[] resultData, ref int currentPosition)
		{
			int res;

			if (BitConverter.IsLittleEndian)
			{
				res = ((resultData[currentPosition++] << 24) | (resultData[currentPosition++] << 16) | (resultData[currentPosition++] << 8) | resultData[currentPosition++]);
			}
			else
			{
				res = (resultData[currentPosition++] | (resultData[currentPosition++] << 8) | (resultData[currentPosition++] << 16) | (resultData[currentPosition++] << 24));
			}

			return res;
		}

		internal static uint ParseUInt(byte[] resultData, ref int currentPosition)
		{
			uint res;

			if (BitConverter.IsLittleEndian)
			{
				res = (((uint) resultData[currentPosition++] << 24) | ((uint) resultData[currentPosition++] << 16) | ((uint) resultData[currentPosition++] << 8) | resultData[currentPosition++]);
			}
			else
			{
				res = (resultData[currentPosition++] | ((uint) resultData[currentPosition++] << 8) | ((uint) resultData[currentPosition++] << 16) | ((uint) resultData[currentPosition++] << 24));
			}

			return res;
		}

		internal static ulong ParseULong(byte[] resultData, ref int currentPosition)
		{
			ulong res;

			if (BitConverter.IsLittleEndian)
			{
				res = ((ulong) ParseUInt(resultData, ref currentPosition) << 32) | ParseUInt(resultData, ref currentPosition);
			}
			else
			{
				res = ParseUInt(resultData, ref currentPosition) | ((ulong) ParseUInt(resultData, ref currentPosition) << 32);
			}

			return res;
		}

		private static DomainName ParseDomainName(byte[] resultData, int currentPosition, out int uncompressedLabelBytes)
		{
			List<string> labels = new List<string>();

			bool isInUncompressedSpace = true;
			uncompressedLabelBytes = 0;

			for (int i = 0; i < 127; i++) // max is 127 labels (see RFC 2065)
			{
				byte currentByte = resultData[currentPosition++];
				if (currentByte == 0)
				{
					// end of domain, RFC1035
					if (isInUncompressedSpace)
						uncompressedLabelBytes += 1;

					return new DomainName(labels.ToArray());
				}
				else if (currentByte >= 192)
				{
					// Pointer, RFC1035

					if (isInUncompressedSpace)
					{
						uncompressedLabelBytes += 2;
						isInUncompressedSpace = false;
					}

					int pointer;
					if (BitConverter.IsLittleEndian)
					{
						pointer = (ushort) (((currentByte - 192) << 8) | resultData[currentPosition]);
					}
					else
					{
						pointer = (ushort) ((currentByte - 192) | (resultData[currentPosition] << 8));
					}

					currentPosition = pointer;
				}
				else if (currentByte == 65)
				{
					// binary EDNS label, RFC2673, RFC3363, RFC3364
					int length = resultData[currentPosition++];
					if (isInUncompressedSpace)
						uncompressedLabelBytes += 1;
					if (length == 0)
						length = 256;

					StringBuilder sb = new StringBuilder();

					sb.Append(@"\[x");
					string suffix = "/" + length + "]";

					do
					{
						currentByte = resultData[currentPosition++];
						if (isInUncompressedSpace)
							uncompressedLabelBytes += 1;

						if (length < 8)
						{
							currentByte &= (byte) (0xff >> (8 - length));
						}

						sb.Append(currentByte.ToString("x2"));

						length = length - 8;
					} while (length > 0);

					sb.Append(suffix);

					labels.Add(sb.ToString());
				}
				else if (currentByte >= 64)
				{
					// extended dns label RFC 2671
					throw new NotSupportedException("Unsupported extended dns label");
				}
				else
				{
					// append additional text part
					if (isInUncompressedSpace)
						uncompressedLabelBytes += 1 + currentByte;

					labels.Add(Encoding.ASCII.GetString(resultData, currentPosition, currentByte));
					currentPosition += currentByte;
				}
			}

			throw new FormatException("Domain name could not be parsed. Invalid message?");
		}

		internal static byte[] ParseByteData(byte[] resultData, ref int currentPosition, int length)
		{
			if (length == 0)
			{
				return new byte[] { };
			}
			else
			{
				byte[] res = new byte[length];
				Buffer.BlockCopy(resultData, currentPosition, res, 0, length);
				currentPosition += length;
				return res;
			}
		}
		#endregion

		#endregion

		#region Serializing
		protected virtual void PrepareEncoding() {}

		internal int Encode(bool addLengthPrefix, out byte[] messageData)
		{
			byte[] newTSigMac;

			return Encode(addLengthPrefix, null, false, out messageData, out newTSigMac);
		}

		internal int Encode(bool addLengthPrefix, byte[] originalTsigMac, out byte[] messageData)
		{
			byte[] newTSigMac;

			return Encode(addLengthPrefix, originalTsigMac, false, out messageData, out newTSigMac);
		}

		internal int Encode(bool addLengthPrefix, byte[] originalTsigMac, bool isSubSequentResponse, out byte[] messageData, out byte[] newTSigMac)
		{
			PrepareEncoding();

			int offset = 0;
			int messageOffset = offset;
			int maxLength = addLengthPrefix ? 2 : 0;

			originalTsigMac = originalTsigMac ?? new byte[] { };

			if (TSigOptions != null)
			{
				if (!IsQuery)
				{
					offset += 2 + originalTsigMac.Length;
					maxLength += 2 + originalTsigMac.Length;
				}

				maxLength += TSigOptions.MaximumLength;
			}

			#region Get Message Length
			maxLength += 12;
			maxLength += Questions.Sum(question => question.MaximumLength);
			maxLength += AnswerRecords.Sum(record => record.MaximumLength);
			maxLength += AuthorityRecords.Sum(record => record.MaximumLength);
			maxLength += _additionalRecords.Sum(record => record.MaximumLength);
			#endregion

			messageData = new byte[maxLength];
			int currentPosition = offset;

			Dictionary<DomainName, ushort> domainNames = new Dictionary<DomainName, ushort>();

			EncodeUShort(messageData, ref currentPosition, TransactionID);
			EncodeUShort(messageData, ref currentPosition, Flags);
			EncodeUShort(messageData, ref currentPosition, (ushort) Questions.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort) AnswerRecords.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort) AuthorityRecords.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort) _additionalRecords.Count);

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
			foreach (DnsRecordBase record in _additionalRecords)
			{
				record.Encode(messageData, offset, ref currentPosition, domainNames);
			}

			if (TSigOptions == null)
			{
				newTSigMac = null;
			}
			else
			{
				if (!IsQuery)
				{
					EncodeUShort(messageData, messageOffset, (ushort) originalTsigMac.Length);
					Buffer.BlockCopy(originalTsigMac, 0, messageData, messageOffset + 2, originalTsigMac.Length);
				}

				EncodeUShort(messageData, offset, TSigOptions.OriginalID);

				int tsigVariablesPosition = currentPosition;

				if (isSubSequentResponse)
				{
					TSigRecord.EncodeDateTime(messageData, ref tsigVariablesPosition, TSigOptions.TimeSigned);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.Fudge.TotalSeconds);
				}
				else
				{
					EncodeDomainName(messageData, offset, ref tsigVariablesPosition, TSigOptions.Name, null, false);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.RecordClass);
					EncodeInt(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.TimeToLive);
					EncodeDomainName(messageData, offset, ref tsigVariablesPosition, TSigAlgorithmHelper.GetDomainName(TSigOptions.Algorithm), null, false);
					TSigRecord.EncodeDateTime(messageData, ref tsigVariablesPosition, TSigOptions.TimeSigned);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.Fudge.TotalSeconds);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.Error);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.OtherData.Length);
					EncodeByteArray(messageData, ref tsigVariablesPosition, TSigOptions.OtherData);
				}

				KeyedHashAlgorithm hashAlgorithm = TSigAlgorithmHelper.GetHashAlgorithm(TSigOptions.Algorithm);
				if ((hashAlgorithm != null) && (TSigOptions.KeyData != null) && (TSigOptions.KeyData.Length > 0))
				{
					hashAlgorithm.Key = TSigOptions.KeyData;
					newTSigMac = hashAlgorithm.ComputeHash(messageData, messageOffset, tsigVariablesPosition);
				}
				else
				{
					newTSigMac = new byte[] { };
				}

				EncodeUShort(messageData, offset, TransactionID);
				EncodeUShort(messageData, offset + 10, (ushort) (_additionalRecords.Count + 1));

				TSigOptions.Encode(messageData, offset, ref currentPosition, domainNames, newTSigMac);

				if (!IsQuery)
				{
					Buffer.BlockCopy(messageData, offset, messageData, messageOffset, (currentPosition - offset));
					currentPosition -= (2 + originalTsigMac.Length);
				}
			}

			if (addLengthPrefix)
			{
				Buffer.BlockCopy(messageData, 0, messageData, 2, currentPosition);
				EncodeUShort(messageData, 0, (ushort) (currentPosition));
				currentPosition += 2;
			}

			return currentPosition;
		}

		internal static void EncodeUShort(byte[] buffer, int currentPosition, ushort value)
		{
			EncodeUShort(buffer, ref currentPosition, value);
		}

		internal static void EncodeUShort(byte[] buffer, ref int currentPosition, ushort value)
		{
			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition++] = (byte) ((value >> 8) & 0xff);
				buffer[currentPosition++] = (byte) (value & 0xff);
			}
			else
			{
				buffer[currentPosition++] = (byte) (value & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 8) & 0xff);
			}
		}

		internal static void EncodeInt(byte[] buffer, ref int currentPosition, int value)
		{
			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition++] = (byte) ((value >> 24) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 8) & 0xff);
				buffer[currentPosition++] = (byte) (value & 0xff);
			}
			else
			{
				buffer[currentPosition++] = (byte) (value & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 8) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 24) & 0xff);
			}
		}

		internal static void EncodeUInt(byte[] buffer, ref int currentPosition, uint value)
		{
			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition++] = (byte) ((value >> 24) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 8) & 0xff);
				buffer[currentPosition++] = (byte) (value & 0xff);
			}
			else
			{
				buffer[currentPosition++] = (byte) (value & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 8) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((value >> 24) & 0xff);
			}
		}

		internal static void EncodeULong(byte[] buffer, ref int currentPosition, ulong value)
		{
			if (BitConverter.IsLittleEndian)
			{
				EncodeUInt(buffer, ref currentPosition, (uint) ((value >> 32) & 0xffffffff));
				EncodeUInt(buffer, ref currentPosition, (uint) (value & 0xffffffff));
			}
			else
			{
				EncodeUInt(buffer, ref currentPosition, (uint) (value & 0xffffffff));
				EncodeUInt(buffer, ref currentPosition, (uint) ((value >> 32) & 0xffffffff));
			}
		}

		internal static void EncodeDomainName(byte[] messageData, int offset, ref int currentPosition, DomainName name, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			if (name.LabelCount == 0)
			{
				messageData[currentPosition++] = 0;
				return;
			}

			bool isCompressionAllowed = !useCanonical & (domainNames != null);

			ushort pointer;
			if (isCompressionAllowed && domainNames.TryGetValue(name, out pointer))
			{
				EncodeUShort(messageData, ref currentPosition, pointer);
				return;
			}

			string label = name.Labels[0];

			if (isCompressionAllowed)
				domainNames[name] = (ushort) ((currentPosition | 0xc000) - offset);

			messageData[currentPosition++] = (byte) label.Length;

			if (useCanonical)
				label = label.ToLowerInvariant();

			EncodeByteArray(messageData, ref currentPosition, Encoding.ASCII.GetBytes(label));

			EncodeDomainName(messageData, offset, ref currentPosition, name.GetParentName(), domainNames, useCanonical);
		}

		internal static void EncodeTextBlock(byte[] messageData, ref int currentPosition, string text)
		{
			byte[] textData = Encoding.ASCII.GetBytes(text);

			for (int i = 0; i < textData.Length; i += 255)
			{
				int blockLength = Math.Min(255, (textData.Length - i));
				messageData[currentPosition++] = (byte) blockLength;

				Buffer.BlockCopy(textData, i, messageData, currentPosition, blockLength);
				currentPosition += blockLength;
			}
		}

		internal static void EncodeTextWithoutLength(byte[] messageData, ref int currentPosition, string text)
		{
			byte[] textData = Encoding.ASCII.GetBytes(text);
			Buffer.BlockCopy(textData, 0, messageData, currentPosition, textData.Length);
			currentPosition += textData.Length;
		}

		internal static void EncodeByteArray(byte[] messageData, ref int currentPosition, byte[] data)
		{
			if (data != null)
			{
				EncodeByteArray(messageData, ref currentPosition, data, data.Length);
			}
		}

		internal static void EncodeByteArray(byte[] messageData, ref int currentPosition, byte[] data, int length)
		{
			if ((data != null) && (length > 0))
			{
				Buffer.BlockCopy(data, 0, messageData, currentPosition, length);
				currentPosition += length;
			}
		}
		#endregion
	}
}