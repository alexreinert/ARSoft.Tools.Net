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

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///   <para>ISDN address</para>
    ///   <para>
    ///     Defined in
    ///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
    ///   </para>
    /// </summary>
    public class IsdnRecord : DnsRecordBase
	{
		/// <summary>
		///   ISDN number
		/// </summary>
		public string IsdnAddress { get; private set; }

		/// <summary>
		///   Sub address
		/// </summary>
		public string SubAddress { get; private set; }

		internal IsdnRecord() {}

		/// <summary>
		///   Creates a new instance of the IsdnRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="isdnAddress"> ISDN number </param>
		public IsdnRecord(DomainName name, int timeToLive, string isdnAddress)
			: this(name, timeToLive, isdnAddress, string.Empty) {}

		/// <summary>
		///   Creates a new instance of the IsdnRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="isdnAddress"> ISDN number </param>
		/// <param name="subAddress"> Sub address </param>
		public IsdnRecord(DomainName name, int timeToLive, string isdnAddress, string subAddress)
			: base(name, RecordType.Isdn, RecordClass.INet, timeToLive)
		{
			IsdnAddress = isdnAddress ?? string.Empty;
			SubAddress = subAddress ?? string.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			var endPosition = currentPosition + length;

			IsdnAddress = DnsMessageBase.ParseText(resultData, ref currentPosition);
			SubAddress = currentPosition < endPosition ? DnsMessageBase.ParseText(resultData, ref currentPosition) : string.Empty;
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length > 2)
				throw new FormatException();

			IsdnAddress = stringRepresentation[0];

			if (stringRepresentation.Length > 1)
				SubAddress = stringRepresentation[1];
		}

		internal override string RecordDataToString() => IsdnAddress.ToMasterfileLabelRepresentation()
		                                                 + (string.IsNullOrEmpty(SubAddress) ? string.Empty : " " + SubAddress.ToMasterfileLabelRepresentation());

	    protected internal override int MaximumRecordDataLength => 2 + IsdnAddress.Length + SubAddress.Length;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, IsdnAddress);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, SubAddress);
		}
	}
}