#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>X.400 mail mapping information record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc2163.html">RFC 2163</a>.
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

		internal PxRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, byte[] resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Map822 = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
			MapX400 = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
		}

		internal PxRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 3)
				throw new FormatException();

			Preference = UInt16.Parse(stringRepresentation[0]);
			Map822 = ParseDomainName(origin, stringRepresentation[1]);
			MapX400 = ParseDomainName(origin, stringRepresentation[2]);
		}

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

		internal override string RecordDataToString()
		{
			return Preference
			       + " " + Map822
			       + " " + MapX400;
		}

		protected internal override int MaximumRecordDataLength => 6 + Map822.MaximumRecordDataLength + MapX400.MaximumRecordDataLength;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Map822, null, useCanonical);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, MapX400, null, useCanonical);
		}
	}
}