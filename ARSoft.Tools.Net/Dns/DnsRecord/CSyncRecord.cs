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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Child-to-Parent Synchronization</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc7477">RFC 7477</see>
	///   </para>
	/// </summary>
	public class CSyncRecord : DnsRecordBase
	{
		/// <summary>
		///   CSync record flags
		/// </summary>
		public enum CSyncFlags : ushort
		{
			/// <summary>
			///   <para>Immediate</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc7477">RFC 7477</see>
			///   </para>
			/// </summary>
			Immediate = 1,

			/// <summary>
			///   <para>SOA minimum</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc7477">RFC 7477</see>
			///   </para>
			/// </summary>
			SoaMinimum = 2,
		}

		/// <summary>
		///   SOA Serial Field
		/// </summary>
		public uint SerialNumber { get; internal set; }

		/// <summary>
		///   Flags
		/// </summary>
		public CSyncFlags Flags { get; internal set; }

		/// <summary>
		///   Record types
		/// </summary>
		public List<RecordType> Types { get; private set; }

		internal CSyncRecord() {}

		/// <summary>
		///   Creates a new instance of the CSyncRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="serialNumber"> SOA Serial Field </param>
		/// <param name="flags"> Flags</param>
		/// <param name="types"> Record types of the next owner </param>
		public CSyncRecord(DomainName name, RecordClass recordClass, int timeToLive, uint serialNumber, CSyncFlags flags, List<RecordType> types)
			: base(name, RecordType.CSync, recordClass, timeToLive)
		{
			SerialNumber = serialNumber;
			Flags = flags;

			if ((types == null) || (types.Count == 0))
			{
				Types = new List<RecordType>();
			}
			else
			{
				Types = types.Distinct().OrderBy(x => x).ToList();
			}
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			SerialNumber = DnsMessageBase.ParseUInt(resultData, ref currentPosition);
			Flags = (CSyncFlags) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Types = ParseTypeBitMap(resultData, ref currentPosition, endPosition);
		}

		internal static List<RecordType> ParseTypeBitMap(byte[] resultData, ref int currentPosition, int endPosition)
		{
			List<RecordType> types = new List<RecordType>();
			while (currentPosition < endPosition)
			{
				byte windowNumber = resultData[currentPosition++];
				byte windowLength = resultData[currentPosition++];

				for (int i = 0; i < windowLength; i++)
				{
					byte bitmap = resultData[currentPosition++];

					for (int bit = 0; bit < 8; bit++)
					{
						if ((bitmap & (1 << Math.Abs(bit - 7))) != 0)
						{
							types.Add((RecordType) (windowNumber * 256 + i * 8 + bit));
						}
					}
				}
			}
			return types;
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length < 3)
				throw new FormatException();

			SerialNumber = UInt32.Parse(stringRepresentation[0]);
			Flags = (CSyncFlags) UInt16.Parse(stringRepresentation[1]);
			Types = stringRepresentation.Skip(2).Select(RecordTypeHelper.ParseShortString).ToList();
		}

		internal override string RecordDataToString()
		{
			return SerialNumber
			       + " " + (ushort) Flags + " " + String.Join(" ", Types.Select(RecordTypeHelper.ToShortString));
		}

		protected internal override int MaximumRecordDataLength => 7 + GetMaximumTypeBitmapLength(Types);

		internal static int GetMaximumTypeBitmapLength(List<RecordType> types)
		{
			int res = 0;

			int windowEnd = 255;
			ushort lastType = 0;

			foreach (ushort type in types.Select(t => (ushort) t))
			{
				if (type > windowEnd)
				{
					res += 3 + lastType % 256 / 8;
					windowEnd = (type / 256 + 1) * 256 - 1;
				}

				lastType = type;
			}

			return res + 3 + lastType % 256 / 8;
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUInt(messageData, ref currentPosition, SerialNumber);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Flags);
			EncodeTypeBitmap(messageData, ref currentPosition, Types);
		}

		internal static void EncodeTypeBitmap(byte[] messageData, ref int currentPosition, List<RecordType> types)
		{
			int windowEnd = 255;
			byte[] windowData = new byte[32];
			int windowLength = 0;

			foreach (ushort type in types.Select(t => (ushort) t))
			{
				if (type > windowEnd)
				{
					if (windowLength > 0)
					{
						messageData[currentPosition++] = (byte) (windowEnd / 256);
						messageData[currentPosition++] = (byte) windowLength;
						DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, windowData, windowLength);
					}

					windowEnd = (type / 256 + 1) * 256 - 1;
					windowLength = 0;
				}

				int typeLower = type % 256;

				int octetPos = typeLower / 8;
				int bitPos = typeLower % 8;

				while (windowLength <= octetPos)
				{
					windowData[windowLength] = 0;
					windowLength++;
				}

				byte octet = windowData[octetPos];
				octet |= (byte) (1 << Math.Abs(bitPos - 7));
				windowData[octetPos] = octet;
			}

			if (windowLength > 0)
			{
				messageData[currentPosition++] = (byte) (windowEnd / 256);
				messageData[currentPosition++] = (byte) windowLength;
				DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, windowData, windowLength);
			}
		}
	}
}