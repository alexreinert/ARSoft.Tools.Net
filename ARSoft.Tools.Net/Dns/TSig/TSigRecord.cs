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

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Transaction signature record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc2845.html">RFC 2845</a>,
	///     <a href="https://www.rfc-editor.org/rfc/rfc4635.html">RFC 4635</a>
	///     and <a href="https://www.rfc-editor.org/rfc/rfc8945.html">RFC 8945</a>
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public class TSigRecord : DnsRecordBase
	{
		private readonly int _startPosition;

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public TSigAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Time when the data was signed
		/// </summary>
		public DateTime TimeSigned { get; internal set; }

		/// <summary>
		///   Timespan errors permitted
		/// </summary>
		public TimeSpan Fudge { get; private set; }

		/// <summary>
		///   MAC defined by algorithm
		/// </summary>
		public byte[] Mac { get; internal set; }

		/// <summary>
		///   Original ID of message
		/// </summary>
		public ushort OriginalID { get; private set; }

		/// <summary>
		///   Error field
		/// </summary>
		public ReturnCode Error { get; internal set; }

		/// <summary>
		///   Binary other data
		/// </summary>
		public byte[] OtherData { get; internal set; }

		/// <summary>
		///   Binary data of the key
		/// </summary>
		public byte[]? KeyData { get; internal set; }

		/// <summary>
		///   Result of validation of record
		/// </summary>
		public ReturnCode ValidationResult { get; internal set; }

		internal TSigRecord(int startPosition, DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			_startPosition = startPosition;
			Algorithm = TSigAlgorithmHelper.GetAlgorithmByName(DnsMessageBase.ParseDomainName(resultData, ref currentPosition));
			TimeSigned = ParseDateTime(resultData, ref currentPosition);
			Fudge = TimeSpan.FromSeconds(DnsMessageBase.ParseUShort(resultData, ref currentPosition));
			int macSize = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Mac = DnsMessageBase.ParseByteData(resultData, ref currentPosition, macSize);
			OriginalID = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Error = (ReturnCode) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int otherDataSize = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			OtherData = DnsMessageBase.ParseByteData(resultData, ref currentPosition, otherDataSize);
		}

		internal TSigRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		///   Creates a new instance of the TSigRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="timeSigned"> Time when the data was signed </param>
		/// <param name="fudge"> Timespan errors permitted </param>
		/// <param name="originalID"> Original ID of message </param>
		/// <param name="error"> Error field </param>
		/// <param name="otherData"> Binary other data </param>
		/// <param name="keyData"> Binary data of the key </param>
		public TSigRecord(DomainName name, TSigAlgorithm algorithm, DateTime timeSigned, TimeSpan fudge, ushort originalID, ReturnCode error, byte[]? otherData, byte[]? keyData)
			: base(name, RecordType.TSig, RecordClass.Any, 0)
		{
			Algorithm = algorithm;
			TimeSigned = timeSigned;
			Fudge = fudge;
			Mac = new byte[] { };
			OriginalID = originalID;
			Error = error;
			OtherData = otherData ?? new byte[] { };
			KeyData = keyData;
		}

		internal override string RecordDataToString()
		{
			return TSigAlgorithmHelper.GetDomainName(Algorithm).ToString(false)
			       + " " + (int) (TimeSigned - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
			       + " " + (ushort) Fudge.TotalSeconds
			       + " " + Mac.Length
			       + " " + Mac.ToBase64String()
			       + " " + OriginalID
			       + " " + (ushort) Error
			       + " " + OtherData.Length
			       + " " + OtherData.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength => TSigAlgorithmHelper.GetDomainName(Algorithm).MaximumRecordDataLength + 18 + TSigAlgorithmHelper.GetMaxHashSize(Algorithm) + OtherData.Length;

		internal void Encode(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, byte[] mac)
		{
			EncodeRecordHeader(messageData, ref currentPosition, domainNames, false);
			var recordDataOffset = currentPosition + 2;
			EncodeRecordData(messageData, ref recordDataOffset, mac);
			EncodeRecordLength(messageData, ref currentPosition, recordDataOffset);
		}

		private void EncodeRecordData(IList<byte> messageData, ref int currentPosition, byte[] mac)
		{
			DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, TSigAlgorithmHelper.GetDomainName(Algorithm), null, false);
			EncodeDateTime(messageData, ref currentPosition, TimeSigned);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Fudge.TotalSeconds);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) mac.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, mac);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, OriginalID);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Error);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) OtherData.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, OtherData);
		}

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			EncodeRecordData(messageData, ref currentPosition, Mac);
		}

		internal static void EncodeDateTime(IList<byte> buffer, ref int currentPosition, DateTime value)
		{
			long timeStamp = (long) (value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition++] = (byte) ((timeStamp >> 40) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 32) & 0xff);
				buffer[currentPosition++] = (byte) (timeStamp >> 24 & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 8) & 0xff);
				buffer[currentPosition++] = (byte) (timeStamp & 0xff);
			}
			else
			{
				buffer[currentPosition++] = (byte) (timeStamp & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 8) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 24) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 32) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 40) & 0xff);
			}
		}

		private static DateTime ParseDateTime(IList<byte> buffer, ref int currentPosition)
		{
			long timeStamp;

			if (BitConverter.IsLittleEndian)
			{
				timeStamp = ((buffer[currentPosition++] << 40) | (buffer[currentPosition++] << 32) | buffer[currentPosition++] << 24 | (buffer[currentPosition++] << 16) | (buffer[currentPosition++] << 8) | buffer[currentPosition++]);
			}
			else
			{
				timeStamp = (buffer[currentPosition++] | (buffer[currentPosition++] << 8) | (buffer[currentPosition++] << 16) | (buffer[currentPosition++] << 24) | (buffer[currentPosition++] << 32) | (buffer[currentPosition++] << 40));
			}

			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp).ToLocalTime();
		}

		internal ReturnCode ValidateTSig(IList<byte> resultData, int additionalRecordCount, DnsServer.SelectTsigKey? tsigKeySelector, byte[]? originalMac)
		{
			byte[]? keyData;
			if (this.Algorithm == TSigAlgorithm.Unknown)
				return ReturnCode.BadAlg;

			if (this.Mac.Length == 0)
			{
				return ReturnCode.BadSig;
			}

			var hashAlgorithm = TSigAlgorithmHelper.GetHashAlgorithm(this.Algorithm);
			if (hashAlgorithm == null)
				return ReturnCode.BadAlg;

			if ((this.Mac.Length > hashAlgorithm.GetMacSize()))
				return ReturnCode.FormatError;

			if ((this.Mac.Length < 10) || (this.Mac.Length < hashAlgorithm.GetMacSize() / 2))
				return ReturnCode.FormatError;

			if ((tsigKeySelector == null) || ((keyData = tsigKeySelector(this.Algorithm, this.Mac.Length < hashAlgorithm.GetMacSize(), this.Name)) == null))
				return ReturnCode.BadKey;

			// maxLength for the buffer to validate: Original (unsigned) dns message and encoded TSigOptions
			// because of compression of keyname, the size of the signed message can not be used
			var maxLength = this._startPosition + this.MaximumLength;
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
				DnsMessageBase.EncodeUShort(validationBuffer, ref currentPosition, (ushort) originalMac.Length);
				DnsMessageBase.EncodeByteArray(validationBuffer, ref currentPosition, originalMac);
			}

			int messageStartPosition = currentPosition;

			// original unsiged buffer
			DnsMessageBase.EncodeByteList(validationBuffer, ref currentPosition, resultData, 0, _startPosition);

			// update original transaction id and ar count in message
			DnsMessageBase.EncodeUShort(validationBuffer, messageStartPosition, this.OriginalID);
			DnsMessageBase.EncodeUShort(validationBuffer, messageStartPosition + 10, (ushort) additionalRecordCount);

			// TSig Variables
			DnsMessageBase.EncodeDomainName(validationBuffer, ref currentPosition, this.Name, null, false);
			DnsMessageBase.EncodeUShort(validationBuffer, ref currentPosition, (ushort) this.RecordClass);
			DnsMessageBase.EncodeInt(validationBuffer, ref currentPosition, (ushort) this.TimeToLive);
			DnsMessageBase.EncodeDomainName(validationBuffer, ref currentPosition, TSigAlgorithmHelper.GetDomainName(this.Algorithm), null, false);
			TSigRecord.EncodeDateTime(validationBuffer, ref currentPosition, this.TimeSigned);
			DnsMessageBase.EncodeUShort(validationBuffer, ref currentPosition, (ushort) this.Fudge.TotalSeconds);
			DnsMessageBase.EncodeUShort(validationBuffer, ref currentPosition, (ushort) this.Error);
			DnsMessageBase.EncodeUShort(validationBuffer, ref currentPosition, (ushort) this.OtherData.Length);
			DnsMessageBase.EncodeByteArray(validationBuffer, ref currentPosition, this.OtherData);

			var hash = new byte[hashAlgorithm.GetMacSize()];

			hashAlgorithm.Init(new KeyParameter(keyData));
			hashAlgorithm.BlockUpdate(validationBuffer, 0, currentPosition);
			hashAlgorithm.DoFinal(hash, 0);

			if (!hash.Take(this.Mac.Length).SequenceEqual(this.Mac))
				return ReturnCode.BadSig;

			if (((this.TimeSigned - this.Fudge) > DateTime.Now) || ((this.TimeSigned + this.Fudge) < DateTime.Now))
				return ReturnCode.BadTime;

			this.KeyData = keyData;

			return ReturnCode.NoError;
		}
	}
}