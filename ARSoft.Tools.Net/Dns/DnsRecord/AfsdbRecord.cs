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
	///   <para>AFS data base location</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>
	///     and
	///     <a href="https://www.rfc-editor.org/rfc/rfc5864.html">RFC 5864</a>.
	///   </para>
	/// </summary>
	public class AfsdbRecord : DnsRecordBase
	{
		/// <summary>
		///   AFS database subtype
		/// </summary>
		public enum AfsSubType : ushort
		{
			/// <summary>
			///   <para>Andrews File Service v3.0 Location service</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>.
			///   </para>
			/// </summary>
			Afs = 1,

			/// <summary>
			///   <para>DCE/NCA root cell directory node</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>.
			///   </para>
			/// </summary>
			Dce = 2,
		}

		/// <summary>
		///   Subtype of the record
		/// </summary>
		public AfsSubType SubType { get; private set; }

		/// <summary>
		///   Hostname of the AFS database
		/// </summary>
		public DomainName Hostname { get; private set; }

		internal AfsdbRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			SubType = (AfsSubType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Hostname = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
		}

		internal AfsdbRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 2)
				throw new FormatException();

			SubType = (AfsSubType) Byte.Parse(stringRepresentation[0]);
			Hostname = ParseDomainName(origin, stringRepresentation[1]);
		}

		/// <summary>
		///   Creates a new instance of the AfsdbRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="subType"> Subtype of the record </param>
		/// <param name="hostname"> Hostname of the AFS database </param>
		public AfsdbRecord(DomainName name, int timeToLive, AfsSubType subType, DomainName hostname)
			: base(name, RecordType.Afsdb, RecordClass.INet, timeToLive)
		{
			SubType = subType;
			Hostname = hostname ?? DomainName.Root;
		}

		internal override string RecordDataToString()
		{
			return (byte) SubType
			       + " " + Hostname;
		}

		protected internal override int MaximumRecordDataLength => Hostname.MaximumRecordDataLength + 4;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) SubType);
			DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, Hostname, null, useCanonical);
		}
	}
}