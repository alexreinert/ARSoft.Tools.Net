#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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

using System.Collections;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Xml;
using ARSoft.Tools.Net.Dns.DynamicUpdate;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Base class for a dns message
	/// </summary>
	[JsonConverter(typeof(Rfc8427JsonConverter<DnsMessageBase>))]
	public abstract class DnsMessageBase
	{
		private static readonly SecureRandom _secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

		protected ushort Flags;

		/// <summary>
		///   Gets or sets the entries in the additional records section
		/// </summary>
		public List<DnsRecordBase> AdditionalRecords { get; set; } = new();

		internal abstract bool IsReliableSendingRequested { get; }
		internal abstract bool IsReliableResendingRequested { get; }
		internal abstract bool IsNextMessageWaiting(bool isSubsequentResponseMessage);

		protected internal abstract DnsMessageBase CreateFailureResponse();

		#region Header
		/// <summary>
		///   Gets or sets the transaction identifier (ID) of the message
		/// </summary>
		public ushort TransactionID { get; set; } = (ushort) _secureRandom.Next(1, 0xffff);

		/// <summary>
		///   Gets or sets the query (QR) flag
		/// </summary>
		public bool IsQuery
		{
			get => (Flags & 0x8000) == 0;
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

		protected OperationCode OperationCodeInternal
		{
			get => (OperationCode) ((Flags & 0x7800) >> 11);
			set
			{
				var clearedOp = (ushort) (Flags & 0x8700);
				Flags = (ushort) (clearedOp | (ushort) value << 11);
			}
		}

		protected internal bool AAFlagInternal
		{
			get => (Flags & 0x0400) != 0;
			set
			{
				if (value)
				{
					Flags |= 0x0400;
				}
				else
				{
					Flags &= 0xfbff;
				}
			}
		}

		protected internal bool TCFlagInternal
		{
			get => (Flags & 0x0200) != 0;
			set
			{
				if (value)
				{
					Flags |= 0x0200;
				}
				else
				{
					Flags &= 0xfdff;
				}
			}
		}

		protected internal bool RDFlagInternal
		{
			get => (Flags & 0x0100) != 0;
			set
			{
				if (value)
				{
					Flags |= 0x0100;
				}
				else
				{
					Flags &= 0xfeff;
				}
			}
		}

		protected internal bool RAFlagInternal
		{
			get => (Flags & 0x0080) != 0;
			set
			{
				if (value)
				{
					Flags |= 0x0080;
				}
				else
				{
					Flags &= 0xff7f;
				}
			}
		}

		protected internal bool ADFlagInternal
		{
			get => (Flags & 0x0020) != 0;
			set
			{
				if (value)
				{
					Flags |= 0x0020;
				}
				else
				{
					Flags &= 0xffdf;
				}
			}
		}

		protected internal bool CDFlagInternal
		{
			get => (Flags & 0x0010) != 0;
			set
			{
				if (value)
				{
					Flags |= 0x0010;
				}
				else
				{
					Flags &= 0xffef;
				}
			}
		}

		/// <summary>
		///   Gets or sets the return code (RCODE)
		/// </summary>
		public ReturnCode ReturnCode
		{
			get
			{
				var rcode = (ReturnCode) (Flags & 0x000f);

				var ednsOptions = EDnsOptions;
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
				var ednsOptions = EDnsOptions;

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

				var clearedOp = (ushort) (Flags & 0xfff0);
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
			get => AdditionalRecords.Any(record => (record.RecordType == RecordType.Opt));
			set
			{
				if (value && !IsEDnsEnabled)
				{
					AdditionalRecords.Add(new OptRecord());
				}
				else if (!value && IsEDnsEnabled)
				{
					AdditionalRecords.RemoveAll(record => (record.RecordType == RecordType.Opt));
				}
			}
		}

		/// <summary>
		///   Gets or set the OptRecord for the EDNS options
		/// </summary>
		public OptRecord? EDnsOptions
		{
			get => (OptRecord?) AdditionalRecords?.Find(record => (record.RecordType == RecordType.Opt));
			set
			{
				if (value == null)
				{
					IsEDnsEnabled = false;
				}
				else if (IsEDnsEnabled)
				{
					var pos = AdditionalRecords.FindIndex(record => (record.RecordType == RecordType.Opt));
					AdditionalRecords[pos] = value;
				}
				else
				{
					AdditionalRecords.Add(value);
				}
			}
		}
		#endregion

		#region TSig
		/// <summary>
		///   Gets or set the TSigRecord for the tsig signed messages
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public TSigRecord? TSigOptions { get; set; }
		#endregion

		internal static DnsMessageBase CreateByFlag(IList<byte> package, DnsServer.SelectTsigKey? tsigKeySelector, byte[]? originalMac)
		{
			var flagPosition = 2;
			var flags = ParseUShort(package, ref flagPosition);

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

			res.ParseInternal(package, tsigKeySelector, originalMac);

			return res;
		}

		#region Parsing
		internal static TMessage Parse<TMessage>(IList<byte> package)
			where TMessage : DnsMessageBase, new()
		{
			return Parse<TMessage>(package, null, null);
		}

		internal static TMessage Parse<TMessage>(IList<byte> data, DnsServer.SelectTsigKey? tsigKeySelector, byte[]? originalMac)
			where TMessage : DnsMessageBase, new()
		{
			TMessage result = new();
			result.ParseInternal(data, tsigKeySelector, originalMac);
			return result;
		}

		private void ParseInternal(IList<byte> data, DnsServer.SelectTsigKey? tsigKeySelector, byte[]? originalMac)
		{
			int currentPosition = 0;

			ParseHeader(data, ref currentPosition, out int questionCount, out int answerRecordCount, out int authorityRecordCount, out int additionalRecordCount);

			ParseQuestionSection(data, ref currentPosition, questionCount);
			ParseAnswerSection(data, ref currentPosition, answerRecordCount);
			ParseAuthoritySection(data, ref currentPosition, authorityRecordCount);
			AdditionalRecords = ParseRecordSection(data, ref currentPosition, additionalRecordCount);

			if (AdditionalRecords.Count > 0)
			{
				var tSigPos = AdditionalRecords.FindIndex(record => (record.RecordType == RecordType.TSig));
				if (tSigPos == (AdditionalRecords.Count - 1))
				{
					TSigOptions = (TSigRecord) AdditionalRecords[tSigPos];

					AdditionalRecords.RemoveAt(tSigPos);

					TSigOptions.ValidationResult = TSigOptions.ValidateTSig(data, AdditionalRecords.Count, tsigKeySelector, originalMac);
				}
			}
		}

		private void ParseHeader(IList<byte> data, ref int currentPosition, out int questionCount, out int answerRecordCount, out int authorityRecordCount, out int additionalRecordCount)
		{
			TransactionID = ParseUShort(data, ref currentPosition);
			Flags = ParseUShort(data, ref currentPosition);
			questionCount = ParseUShort(data, ref currentPosition);
			answerRecordCount = ParseUShort(data, ref currentPosition);
			authorityRecordCount = ParseUShort(data, ref currentPosition);
			additionalRecordCount = ParseUShort(data, ref currentPosition);
		}

		protected void ParseQuestionSection(IList<byte> data, ref int currentPosition, int recordCount)
		{
			var questions = new List<DnsQuestion>(recordCount);

			for (var i = 0; i < recordCount; i++)
			{
				questions.Add(DnsQuestion.Parse(data, ref currentPosition));
			}

			SetQuestionSection(questions);
		}

		protected abstract void ParseAnswerSection(IList<byte> data, ref int currentPosition, int recordCount);

		protected abstract void ParseAuthoritySection(IList<byte> data, ref int currentPosition, int recordCount);

		protected static List<DnsRecordBase> ParseRecordSection(IList<byte> resultData, ref int currentPosition, int recordCount)
		{
			var sectionList = new List<DnsRecordBase>(recordCount);

			for (var i = 0; i < recordCount; i++)
			{
				sectionList.Add(DnsRecordBase.ParseRecordFromMessage(resultData, ref currentPosition));
			}

			return sectionList;
		}

		#region Helper methods for parsing records
		internal static string ParseText(IList<byte> resultData, ref int currentPosition)
		{
			int length = resultData[currentPosition++];
			return ParseText(resultData, ref currentPosition, length);
		}

		internal static string ParseText(IList<byte> resultData, ref int currentPosition, int length)
		{
			return Encoding.ASCII.GetString(ParseByteData(resultData, ref currentPosition, length));
		}

		internal static DomainName ParseDomainName(IList<byte> resultData, ref int currentPosition)
		{
			DomainName res = ParseDomainName(resultData, currentPosition, out var firstLabelLength);
			currentPosition += firstLabelLength;
			return res;
		}

		internal static ushort ParseUShort(IList<byte> resultData, ref int currentPosition)
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

		internal static int ParseInt(IList<byte> resultData, ref int currentPosition)
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

		internal static uint ParseUInt(IList<byte> resultData, ref int currentPosition)
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

		internal static ulong ParseULong(IList<byte> resultData, ref int currentPosition)
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

		private static DomainName ParseDomainName(IList<byte> resultData, int currentPosition, out int uncompressedLabelBytes)
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

					labels.Add(ParseText(resultData, ref currentPosition, currentByte));
				}
			}

			throw new FormatException("Domain name could not be parsed. Invalid message?");
		}

		internal static byte[] ParseByteData(IList<byte> resultData, ref int currentPosition, int length)
		{
			if (length == 0)
			{
				return Array.Empty<byte>();
			}
			else
			{
				if (resultData is ArraySegment<byte> arraySegment)
				{
					var res = arraySegment.Slice(currentPosition, length).ToArray();
					currentPosition += length;
					return res;
				}
				else if (resultData is byte[] byteArray)
				{
					var res = new byte[length];
					Buffer.BlockCopy(byteArray, currentPosition, res, 0, length);
					currentPosition += length;
					return res;
				}
				else
				{
					var res = new byte[length];
					for (var i = 0; i < length; i++)
					{
						res[i] = resultData[currentPosition++];
					}

					return res;
				}
			}
		}
		#endregion
		#endregion

		#region Serializing
		protected virtual void PrepareEncoding() { }

		internal DnsRawPackage Encode()
		{
			return Encode(null, false, out _);
		}

		internal DnsRawPackage Encode(byte[]? originalTsigMac)
		{
			return Encode(originalTsigMac, false, out _);
		}

		protected abstract int GetSectionsMaxLength();

		protected abstract void EncodeSections(IList<byte> messageData, ref int position, Dictionary<DomainName, ushort> domainNames);

		internal DnsRawPackage Encode(byte[]? originalTsigMac, bool isSubSequentResponse, out byte[]? newTSigMac)
		{
			int messageOffset = DnsRawPackage.LENGTH_HEADER_LENGTH;
			int maxLength = DnsRawPackage.LENGTH_HEADER_LENGTH;

			originalTsigMac ??= Array.Empty<byte>();

			if (TSigOptions != null)
			{
				if (!IsQuery)
				{
					messageOffset += 2 + originalTsigMac.Length;
					maxLength += 2 + originalTsigMac.Length;
				}

				maxLength += TSigOptions.MaximumLength;
			}

			maxLength += GetSectionsMaxLength();

			byte[] buffer = new byte[maxLength];

			ArraySegment<byte> messageData = new ArraySegment<byte>(buffer, messageOffset, maxLength - messageOffset);

			int currentMessageDataPosition = 0;

			EncodeUShort(messageData, ref currentMessageDataPosition, TransactionID);
			EncodeUShort(messageData, ref currentMessageDataPosition, Flags);

			Dictionary<DomainName, ushort> domainNames = new Dictionary<DomainName, ushort>();
			EncodeSections(messageData, ref currentMessageDataPosition, domainNames);

			if (TSigOptions == null)
			{
				newTSigMac = null;
			}
			else
			{
				if (!IsQuery)
				{
					EncodeUShort(buffer, DnsRawPackage.LENGTH_HEADER_LENGTH, (ushort) originalTsigMac.Length);
					Buffer.BlockCopy(originalTsigMac, 0, buffer, DnsRawPackage.LENGTH_HEADER_LENGTH + 2, originalTsigMac.Length);
				}

				EncodeUShort(messageData, 0, TSigOptions.OriginalID);

				int tsigVariablesPosition = currentMessageDataPosition;

				if (isSubSequentResponse)
				{
					TSigRecord.EncodeDateTime(messageData, ref tsigVariablesPosition, TSigOptions.TimeSigned);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.Fudge.TotalSeconds);
				}
				else
				{
					EncodeDomainName(messageData, ref tsigVariablesPosition, TSigOptions.Name, null, false);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.RecordClass);
					EncodeInt(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.TimeToLive);
					EncodeDomainName(messageData, ref tsigVariablesPosition, TSigAlgorithmHelper.GetDomainName(TSigOptions.Algorithm), null, false);
					TSigRecord.EncodeDateTime(messageData, ref tsigVariablesPosition, TSigOptions.TimeSigned);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.Fudge.TotalSeconds);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.Error);
					EncodeUShort(messageData, ref tsigVariablesPosition, (ushort) TSigOptions.OtherData.Length);
					EncodeByteArray(messageData, ref tsigVariablesPosition, TSigOptions.OtherData);
				}

				var hashAlgorithm = TSigAlgorithmHelper.GetHashAlgorithm(TSigOptions.Algorithm);
				if ((hashAlgorithm != null) && (TSigOptions.KeyData != null) && (TSigOptions.KeyData.Length > 0))
				{
					hashAlgorithm.Init(new KeyParameter(TSigOptions.KeyData));
					newTSigMac = new byte[hashAlgorithm.GetMacSize()];
					hashAlgorithm.BlockUpdate(buffer, DnsRawPackage.LENGTH_HEADER_LENGTH, tsigVariablesPosition + messageOffset - DnsRawPackage.LENGTH_HEADER_LENGTH);
					hashAlgorithm.DoFinal(newTSigMac, 0);

					if (!IsQuery && originalTsigMac.Length != 0 && originalTsigMac.Length < hashAlgorithm.GetMacSize())
					{
						newTSigMac = newTSigMac.Take(originalTsigMac.Length).ToArray();
					}
				}
				else
				{
					newTSigMac = Array.Empty<byte>();
				}

				EncodeUShort(messageData, 0, TransactionID);
				EncodeUShort(messageData, 10, (ushort) (AdditionalRecords.Count + 1));

				TSigOptions.Encode(messageData, ref currentMessageDataPosition, domainNames, newTSigMac);
			}

			EncodeUShort(buffer, messageOffset - DnsRawPackage.LENGTH_HEADER_LENGTH, (ushort) currentMessageDataPosition);

			return new DnsRawPackage(new ArraySegment<byte>(buffer, messageOffset - DnsRawPackage.LENGTH_HEADER_LENGTH, currentMessageDataPosition + DnsRawPackage.LENGTH_HEADER_LENGTH), currentMessageDataPosition);
		}

		internal static void EncodeUShort(IList<byte> buffer, int currentPosition, ushort value)
		{
			EncodeUShort(buffer, ref currentPosition, value);
		}

		internal static void EncodeUShort(IList<byte> buffer, ref int currentPosition, ushort value)
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

		internal static void EncodeInt(IList<byte> buffer, ref int currentPosition, int value)
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

		internal static void EncodeUInt(IList<byte> buffer, ref int currentPosition, uint value)
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

		internal static void EncodeULong(IList<byte> buffer, ref int currentPosition, ulong value)
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

		internal static void EncodeDomainName(IList<byte> messageData, ref int currentPosition, DomainName name, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			if (name.LabelCount == 0)
			{
				messageData[currentPosition++] = 0;
				return;
			}

			var isCompressionAllowed = !useCanonical && (domainNames != null);

			if (isCompressionAllowed && domainNames!.TryGetValue(name, out var pointer))
			{
				EncodeUShort(messageData, ref currentPosition, pointer);
				return;
			}

			var label = name.Labels[0];

			if (isCompressionAllowed)
				domainNames![name] = (ushort) (currentPosition | 0xc000);

			messageData[currentPosition++] = (byte) label.Length;

			if (useCanonical)
				label = label.ToLowerInvariant();

			EncodeByteArray(messageData, ref currentPosition, Encoding.ASCII.GetBytes(label));

			EncodeDomainName(messageData, ref currentPosition, name.GetParentName(), domainNames, useCanonical);
		}

		internal static void EncodeTextBlock(IList<byte> messageData, ref int currentPosition, string text)
		{
			var textData = Encoding.ASCII.GetBytes(text);

			for (var i = 0; i < textData.Length; i += 255)
			{
				var blockLength = Math.Min(255, (textData.Length - i));
				messageData[currentPosition++] = (byte) blockLength;
				EncodeByteArray(messageData, ref currentPosition, textData, i, blockLength);
			}
		}

		internal static void EncodeTextWithoutLength(IList<byte> messageData, ref int currentPosition, string text)
		{
			byte[] textData = Encoding.ASCII.GetBytes(text);
			EncodeByteArray(messageData, ref currentPosition, textData, textData.Length);
		}

		internal static void EncodeByteArray(IList<byte> messageData, ref int currentPosition, byte[]? data)
		{
			if (data != null)
			{
				EncodeByteArray(messageData, ref currentPosition, data, data.Length);
			}
		}

		internal static void EncodeByteArray(IList<byte> messageData, ref int currentPosition, byte[] data, int count)
		{
			EncodeByteArray(messageData, ref currentPosition, data, 0, count);
		}

		internal static void EncodeByteArray(IList<byte> messageData, ref int currentPosition, byte[] data, int dataOffset, int count)
		{
			try
			{
				if ((data != null) && (count > 0))
				{
					if (messageData is ArraySegment<byte> arraySegment)
					{
						Buffer.BlockCopy(data, dataOffset, arraySegment.Array!, arraySegment.Offset + currentPosition, count);
						currentPosition += count;
					}
					else if (messageData is byte[] byteArray)
					{
						Buffer.BlockCopy(data, dataOffset, byteArray, currentPosition, count);
						currentPosition += count;
					}
					else
					{
						for (var i = dataOffset; i < (dataOffset + count); i++)
						{
							messageData[currentPosition++] = data[i];
						}
					}
				}
			}
			catch
			{
				throw;
			}
		}

		internal static void EncodeByteList(IList<byte> messageData, ref int currentPosition, IList<byte> data, int dataOffset, int count)
		{
			if (data is ArraySegment<byte> arraySegment)
			{
				if (arraySegment.Array != null)
				{
					EncodeByteArray(messageData, ref currentPosition, arraySegment.Array, arraySegment.Offset + dataOffset, count);
				}
			}
			else if (data is byte[] byteArray)
			{
				EncodeByteArray(messageData, ref currentPosition, byteArray, dataOffset, count);
			}
			else
			{
				for (var i = dataOffset; i < (dataOffset + count); i++)
				{
					messageData[currentPosition++] = data[i];
				}
			}
		}

		internal abstract bool ValidateResponse(DnsMessageBase response);
		#endregion

		protected internal abstract void Add0x20Bits();

		protected internal abstract void AddSubsequentResponse(DnsMessageBase respone);

		protected internal abstract bool AllowMultipleResponses { get; }

		protected internal abstract IEnumerable<DnsMessageBase> SplitResponse();

		internal void WriteRfc8427Json(Utf8JsonWriter writer, JsonSerializerOptions options)
		{
			writer.WriteStartObject();

			writer.WriteNumber("ID", TransactionID);
			writer.WriteNumber("QR", IsQuery ? 0 : 1);
			writer.WriteNumber("Opcode", (ushort) OperationCodeInternal);
			writer.WriteNumber("AA", AAFlagInternal ? 1 : 0);
			writer.WriteNumber("TC", TCFlagInternal ? 1 : 0);
			writer.WriteNumber("RD", RDFlagInternal ? 1 : 0);
			writer.WriteNumber("RA", RAFlagInternal ? 1 : 0);
			writer.WriteNumber("AD", ADFlagInternal ? 1 : 0);
			writer.WriteNumber("CD", CDFlagInternal ? 1 : 0);
			writer.WriteNumber("RCODE", ((ushort) ReturnCode) & 0xf);

			WriteRfc8427JsonSections(writer, options);

			writer.WriteEndObject();
		}

		protected abstract void WriteRfc8427JsonSections(Utf8JsonWriter writer, JsonSerializerOptions options);

		protected void WriteRfc8427JsonSection<T>(string name, List<T> records, Utf8JsonWriter writer, JsonSerializerOptions options)
			where T : DnsMessageEntryBase
		{
			if (records.Count == 0)
				return;

			writer.WriteStartArray(name);

			foreach (var record in records)
			{
				record.WriteRfc8427Json(writer, options);
			}

			writer.WriteEndArray();
		}

		internal static TMessage ParseRfc8427Json<TMessage>(JsonElement json)
			where TMessage : DnsMessageBase, new()
		{
			var msg = new TMessage();

			DomainName? qname = null;
			var qclass = RecordClass.Invalid;
			var qtype = RecordType.Invalid;

			foreach (var prop in json.EnumerateObject())
			{
				if (prop.Value.ValueKind == JsonValueKind.Null)
					continue;

				switch (prop.Name)
				{
					case "ID":
						msg.TransactionID = prop.Value.GetUInt16();
						break;
					case "QR":
						msg.IsQuery = !ReadBoolFlag(prop.Value);
						break;
					case "Opcode":
						msg.OperationCodeInternal = (OperationCode) prop.Value.GetUInt16();
						break;
					case "AA":
						msg.AAFlagInternal = ReadBoolFlag(prop.Value);
						break;
					case "TC":
						msg.TCFlagInternal = ReadBoolFlag(prop.Value);
						break;
					case "RD":
						msg.RDFlagInternal = ReadBoolFlag(prop.Value);
						break;
					case "RA":
						msg.RAFlagInternal = ReadBoolFlag(prop.Value);
						break;
					case "AD":
						msg.ADFlagInternal = ReadBoolFlag(prop.Value);
						break;
					case "CD":
						msg.CDFlagInternal = ReadBoolFlag(prop.Value);
						break;
					case "RCODE":
						msg.ReturnCode = (ReturnCode) prop.Value.GetUInt16();
						break;
					case "QNAME":
						qname = DomainName.Parse(prop.Value.GetString() ?? String.Empty);
						break;
					case "QTYPE":
						qtype = (RecordType) prop.Value.GetUInt16();
						break;
					case "QTYPEname":
						qtype = RecordTypeHelper.ParseShortString(prop.Value.GetString() ?? String.Empty);
						break;
					case "QCLASS":
						qclass = (RecordClass) prop.Value.GetUInt16();
						break;
					case "QCLASSname":
						qclass = RecordClassHelper.ParseShortString(prop.Value.GetString() ?? String.Empty);
						break;
					case "questionRRs":
						msg.ParseRfc8427JsonQuestionSection(prop.Value);
						break;
					case "answerRRs":
						msg.ParseRfc8427JsonAnswerSection(prop.Value);
						break;
					case "authorityRRs":
						msg.ParseRfc8427JsonAuthoritySection(prop.Value);
						break;
					case "additionalRRs":
						msg.AdditionalRecords = ParseRfc8427JsonRecordSection(prop.Value);
						break;
					case "messageOctetsHEX":
						msg.ParseInternal(prop.Value.GetString()!.FromBase16String(), null, null);
						return msg;
				}
			}

			if (!json.TryGetProperty("questionRRs", out _) && (qname != null || qtype != RecordType.Invalid || qclass != RecordClass.Invalid))
				msg.SetQuestionSection(new List<DnsQuestion>() { new(qname ?? DomainName.Root, qtype, qclass) });

			return msg;
		}

		private void ParseRfc8427JsonQuestionSection(JsonElement json)
		{
			var questions = new List<DnsQuestion>();

			foreach (var questionJson in json.EnumerateArray())
			{
				questions.Add(DnsQuestion.ParseRfc8427Json(questionJson));
			}

			SetQuestionSection(questions);
		}

		protected static List<DnsRecordBase> ParseRfc8427JsonRecordSection(JsonElement json)
		{
			var sectionList = new List<DnsRecordBase>();

			foreach (var recordJson in json.EnumerateArray())
			{
				if (recordJson.TryGetProperty("rrSet", out var rrsetArrayJson))
				{
					foreach (var rrsetJson in rrsetArrayJson.EnumerateArray())
					{
						sectionList.Add(DnsRecordBase.ParseRfc8427Json(recordJson, rrsetJson));
					}
				}
				else
				{
					sectionList.Add(DnsRecordBase.ParseRfc8427Json(recordJson, recordJson));
				}
			}

			return sectionList;
		}

		protected abstract void ParseRfc8427JsonAnswerSection(JsonElement json);

		protected abstract void ParseRfc8427JsonAuthoritySection(JsonElement json);

		protected abstract void SetQuestionSection(List<DnsQuestion> questionSection);

		private static bool ReadBoolFlag(JsonElement json)
		{
			switch (json.GetInt32())
			{
				case 0: return false;
				case 1: return true;
				default: throw new JsonException("Not a valid boolean flag: '" + json.GetRawText() + "'");
			}
		}
	}
}