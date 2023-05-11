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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Naming authority pointer record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc2915.html">RFC 2915</a>
	///     ,
	///     <a href="https://www.rfc-editor.org/rfc/rfc2168.html">RFC 2168</a>
	///     and
	///     <a href="https://www.rfc-editor.org/rfc/rfc3403.html">RFC 3403</a>.
	///   </para>
	/// </summary>
	public class NaptrRecord : DnsRecordBase
	{
		/// <summary>
		///   Order of the record
		/// </summary>
		public ushort Order { get; private set; }

		/// <summary>
		///   Preference of record with same order
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   Flags of the record
		/// </summary>
		public string Flags { get; private set; }

		/// <summary>
		///   Available services
		/// </summary>
		public string Services { get; private set; }

		/// <summary>
		///   Substitution expression that is applied to the original string
		/// </summary>
		public string RegExp { get; private set; }

		/// <summary>
		///   The next name to query
		/// </summary>
		public DomainName Replacement { get; private set; }

		internal NaptrRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Order = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Preference = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Flags = DnsMessageBase.ParseText(resultData, ref currentPosition);
			Services = DnsMessageBase.ParseText(resultData, ref currentPosition);
			RegExp = DnsMessageBase.ParseText(resultData, ref currentPosition);
			Replacement = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
		}

		internal NaptrRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 6)
				throw new NotSupportedException();

			Order = UInt16.Parse(stringRepresentation[0]);
			Preference = UInt16.Parse(stringRepresentation[1]);
			Flags = stringRepresentation[2];
			Services = stringRepresentation[3];
			RegExp = stringRepresentation[4];
			Replacement = ParseDomainName(origin, stringRepresentation[5]);
		}

		/// <summary>
		///   Creates a new instance of the NaptrRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="order"> Order of the record </param>
		/// <param name="preference"> Preference of record with same order </param>
		/// <param name="flags"> Flags of the record </param>
		/// <param name="services"> Available services </param>
		/// <param name="regExp"> Substitution expression that is applied to the original string </param>
		/// <param name="replacement"> The next name to query </param>
		public NaptrRecord(DomainName name, int timeToLive, ushort order, ushort preference, string flags, string services, string regExp, DomainName replacement)
			: base(name, RecordType.Naptr, RecordClass.INet, timeToLive)
		{
			Order = order;
			Preference = preference;
			Flags = flags ?? String.Empty;
			Services = services ?? String.Empty;
			RegExp = regExp ?? String.Empty;
			Replacement = replacement ?? DomainName.Root;
		}

		internal override string RecordDataToString()
		{
			return Order
			       + " " + Preference
			       + " \"" + Flags.ToMasterfileLabelRepresentation() + "\""
			       + " \"" + Services.ToMasterfileLabelRepresentation() + "\""
			       + " \"" + RegExp.ToMasterfileLabelRepresentation() + "\""
			       + " " + Replacement.ToString(true);
		}

		protected internal override int MaximumRecordDataLength => Flags.Length + Services.Length + RegExp.Length + Replacement.MaximumRecordDataLength + 13;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Order);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Flags);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Services);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, RegExp);
			DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, Replacement, null, useCanonical);
		}
	}
}