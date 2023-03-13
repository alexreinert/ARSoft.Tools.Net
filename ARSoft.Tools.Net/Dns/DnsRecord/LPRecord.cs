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
	///   <para>LP</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc6742.html">RFC 6742</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public class LPRecord : DnsRecordBase
	{
		/// <summary>
		///   The preference
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   The FQDN
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public DomainName FQDN { get; private set; }

		internal LPRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			FQDN = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
		}

		internal LPRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 2)
				throw new FormatException();

			Preference = UInt16.Parse(stringRepresentation[0]);
			FQDN = ParseDomainName(origin, stringRepresentation[1]);
		}

		/// <summary>
		///   Creates a new instance of the LpRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="preference"> The preference </param>
		/// <param name="fqdn"> The FQDN </param>
		public LPRecord(DomainName name, int timeToLive, ushort preference, DomainName fqdn)
			: base(name, RecordType.LP, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			FQDN = fqdn;
		}

		internal override string RecordDataToString()
		{
			return Preference + " " + FQDN;
		}

		protected internal override int MaximumRecordDataLength => 4 + FQDN.MaximumRecordDataLength;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, FQDN, null, false);
		}
	}
}