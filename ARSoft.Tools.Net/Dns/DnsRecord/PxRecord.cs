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
    ///   <para>X.400 mail mapping information record</para>
    ///   <para>
    ///     Defined in
    ///     <see cref="!:http://tools.ietf.org/html/rfc2163">RFC 2163</see>
    ///   </para>
    /// </summary>
    public class PxRecord : DnsRecordBase
	{
		/// <summary>
		///   Preference of the record
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   Domain name containing the RFC822 domain
		/// </summary>
		public DomainName Map822 { get; private set; }

		/// <summary>
		///   Domain name containing the X.400 part
		/// </summary>
		public DomainName MapX400 { get; private set; }

		internal PxRecord() {}

		/// <summary>
		///   Creates a new instance of the PxRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="preference"> Preference of the record </param>
		/// <param name="map822"> Domain name containing the RFC822 domain </param>
		/// <param name="mapX400"> Domain name containing the X.400 part </param>
		public PxRecord(DomainName name, int timeToLive, ushort preference, DomainName map822, DomainName mapX400)
			: base(name, RecordType.Px, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			Map822 = map822 ?? DomainName.Root;
			MapX400 = mapX400 ?? DomainName.Root;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Map822 = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
			MapX400 = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length != 3)
				throw new FormatException();

			Preference = ushort.Parse(stringRepresentation[0]);
			Map822 = ParseDomainName(origin, stringRepresentation[1]);
			MapX400 = ParseDomainName(origin, stringRepresentation[2]);
		}

		internal override string RecordDataToString() => Preference
		                                                 + " " + Map822
		                                                 + " " + MapX400;

	    protected internal override int MaximumRecordDataLength => 6 + Map822.MaximumRecordDataLength + MapX400.MaximumRecordDataLength;



        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Map822, null, useCanonical);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, MapX400, null, useCanonical);
		}
	}
}