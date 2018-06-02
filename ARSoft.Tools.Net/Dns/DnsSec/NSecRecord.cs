﻿#region Copyright and License
// Copyright 2010..2017 Alexander Reinert
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

using System;
using System.Collections.Generic;
using System.Linq;
using ARSoft.Tools.Net.Dns.DnsRecord;

namespace ARSoft.Tools.Net.Dns.DnsSec
{
    /// <summary>
    ///   <para>Next owner</para>
    ///   <para>
    ///     Defined in
    ///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
    ///     and
    ///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
    ///   </para>
    /// </summary>
    public class NSecRecord : DnsRecordBase
	{
		/// <summary>
		///   Name of next owner
		/// </summary>
		public DomainName NextDomainName { get; internal set; }

		/// <summary>
		///   Record types of the next owner
		/// </summary>
		public List<RecordType> Types { get; private set; }

		internal NSecRecord() {}

		/// <summary>
		///   Creates a new instance of the NSecRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="nextDomainName"> Name of next owner </param>
		/// <param name="types"> Record types of the next owner </param>
		public NSecRecord(DomainName name, RecordClass recordClass, int timeToLive, DomainName nextDomainName, List<RecordType> types)
			: base(name, RecordType.NSec, recordClass, timeToLive)
		{
			NextDomainName = nextDomainName ?? DomainName.Root;

			if (types == null || types.Count == 0)
			    Types = new List<RecordType>();
			else
			    Types = types.Distinct().OrderBy(x => x).ToList();
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			var endPosition = currentPosition + length;

			NextDomainName = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);

			Types = ParseTypeBitMap(resultData, ref currentPosition, endPosition);
		}

		internal static List<RecordType> ParseTypeBitMap(byte[] resultData, ref int currentPosition, int endPosition)
		{
			var types = new List<RecordType>();
			while (currentPosition < endPosition)
			{
				var windowNumber = resultData[currentPosition++];
				var windowLength = resultData[currentPosition++];

				for (var i = 0; i < windowLength; i++)
				{
					var bitmap = resultData[currentPosition++];

					for (var bit = 0; bit < 8; bit++)
					    if ((bitmap & 1 << Math.Abs(bit - 7)) != 0)
					        types.Add((RecordType) (windowNumber * 256 + i * 8 + bit));
				}
			}
			return types;
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length < 2)
				throw new FormatException();

			NextDomainName = ParseDomainName(origin, stringRepresentation[0]);
			Types = stringRepresentation.Skip(1).Select(RecordTypeHelper.ParseShortString).ToList();
		}

		internal override string RecordDataToString() => NextDomainName
		                                                 + " " + string.Join(" ", Types.Select(RecordTypeHelper.ToShortString));

	    protected internal override int MaximumRecordDataLength => 2 + NextDomainName.MaximumRecordDataLength + GetMaximumTypeBitmapLength(Types);



        internal static int GetMaximumTypeBitmapLength(List<RecordType> types)
		{
			var res = 0;

			var windowEnd = 255;
			ushort lastType = 0;

			foreach (var type in types.Select(t => (ushort) t))
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
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, NextDomainName, null, useCanonical);
			EncodeTypeBitmap(messageData, ref currentPosition, Types);
		}

		internal static void EncodeTypeBitmap(byte[] messageData, ref int currentPosition, List<RecordType> types)
		{
			var windowEnd = 255;
			var windowData = new byte[32];
			var windowLength = 0;

			foreach (var type in types.Select(t => (ushort) t))
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

				var typeLower = type % 256;

				var octetPos = typeLower / 8;
				var bitPos = typeLower % 8;

				while (windowLength <= octetPos)
				{
					windowData[windowLength] = 0;
					windowLength++;
				}

				var octet = windowData[octetPos];
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

		internal bool IsCovering(DomainName name, DomainName zone) => name.CompareTo(Name) > 0 && name.CompareTo(NextDomainName) < 0 // within zone
		                                                              || name.CompareTo(Name) > 0 && NextDomainName.Equals(zone);
	}
}