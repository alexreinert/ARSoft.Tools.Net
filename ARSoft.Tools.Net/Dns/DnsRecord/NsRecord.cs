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
	///   <para>Authoritatitve name server record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
	///   </para>
	/// </summary>
	public class NsRecord : DnsRecordBase
	{
		/// <summary>
		///   Name of the authoritatitve nameserver for the zone
		/// </summary>
		public DomainName NameServer { get; private set; }

		internal NsRecord() {}

		/// <summary>
		///   Creates a new instance of the NsRecord class
		/// </summary>
		/// <param name="name"> Domain name of the zone </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="nameServer"> Name of the authoritative name server </param>
		public NsRecord(DomainName name, int timeToLive, DomainName nameServer)
			: base(name, RecordType.Ns, RecordClass.INet, timeToLive)
		{
			NameServer = nameServer ?? DomainName.Root;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			NameServer = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length != 1)
				throw new FormatException();

			NameServer = ParseDomainName(origin, stringRepresentation[0]);
		}

		internal override string RecordDataToString()
		{
			return NameServer.ToString();
		}

		protected internal override int MaximumRecordDataLength => NameServer.MaximumRecordDataLength + 2;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, NameServer, domainNames, useCanonical);
		}
	}
}