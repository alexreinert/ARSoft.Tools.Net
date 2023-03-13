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
	///   <para>Start of zone of authority record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
	///   </para>
	/// </summary>
	public class SoaRecord : DnsRecordBase
	{
		/// <summary>
		///   Hostname of the primary name server
		/// </summary>
		public DomainName MasterName { get; private set; }

		/// <summary>
		///   Mail address of the responsable person. The @ should be replaced by a dot.
		/// </summary>
		public DomainName ResponsibleName { get; private set; }

		/// <summary>
		///   Serial number of the zone
		/// </summary>
		public uint SerialNumber { get; private set; }

		/// <summary>
		///   Seconds before the zone should be refreshed
		/// </summary>
		public int RefreshInterval { get; private set; }

		/// <summary>
		///   Seconds that should be elapsed before retry of failed transfer
		/// </summary>
		public int RetryInterval { get; private set; }

		/// <summary>
		///   Seconds that can elapse before the zone is no longer authorative
		/// </summary>
		public int ExpireInterval { get; private set; }

		/// <summary>
		///   <para>Seconds a negative answer could be cached</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2308.html">RFC 2308</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public int NegativeCachingTTL { get; private set; }

		internal SoaRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			MasterName = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
			ResponsibleName = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);

			SerialNumber = DnsMessageBase.ParseUInt(resultData, ref currentPosition);
			RefreshInterval = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			RetryInterval = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			ExpireInterval = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			NegativeCachingTTL = DnsMessageBase.ParseInt(resultData, ref currentPosition);
		}

		internal SoaRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 7)
				throw new FormatException();

			MasterName = ParseDomainName(origin, stringRepresentation[0]);
			ResponsibleName = ParseDomainName(origin, stringRepresentation[1]);

			SerialNumber = UInt32.Parse(stringRepresentation[2]);
			RefreshInterval = Int32.Parse(stringRepresentation[3]);
			RetryInterval = Int32.Parse(stringRepresentation[4]);
			ExpireInterval = Int32.Parse(stringRepresentation[5]);
			NegativeCachingTTL = Int32.Parse(stringRepresentation[6]);
		}

		/// <summary>
		///   Creates a new instance of the SoaRecord class
		/// </summary>
		/// <param name="name"> Name of the zone </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="masterName"> Hostname of the primary name server </param>
		/// <param name="responsibleName"> Mail address of the responsable person. The @ should be replaced by a dot. </param>
		/// <param name="serialNumber"> Serial number of the zone </param>
		/// <param name="refreshInterval"> Seconds before the zone should be refreshed </param>
		/// <param name="retryInterval"> Seconds that should be elapsed before retry of failed transfer </param>
		/// <param name="expireInterval"> Seconds that can elapse before the zone is no longer authorative </param>
		/// <param name="negativeCachingTTL">
		///   <para>Seconds a negative answer could be cached</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2308.html">RFC 2308</a>.
		///   </para>
		/// </param>
		// ReSharper disable once InconsistentNaming
		public SoaRecord(DomainName name, int timeToLive, DomainName masterName, DomainName responsibleName, uint serialNumber, int refreshInterval, int retryInterval, int expireInterval, int negativeCachingTTL)
			: base(name, RecordType.Soa, RecordClass.INet, timeToLive)
		{
			MasterName = masterName ?? DomainName.Root;
			ResponsibleName = responsibleName ?? DomainName.Root;
			SerialNumber = serialNumber;
			RefreshInterval = refreshInterval;
			RetryInterval = retryInterval;
			ExpireInterval = expireInterval;
			NegativeCachingTTL = negativeCachingTTL;
		}

		internal override string RecordDataToString()
		{
			return MasterName
			       + " " + ResponsibleName
			       + " " + SerialNumber
			       + " " + RefreshInterval
			       + " " + RetryInterval
			       + " " + ExpireInterval
			       + " " + NegativeCachingTTL;
		}

		protected internal override int MaximumRecordDataLength => MasterName.MaximumRecordDataLength + ResponsibleName.MaximumRecordDataLength + 24;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, MasterName, domainNames, useCanonical);
			DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, ResponsibleName, domainNames, useCanonical);
			DnsMessageBase.EncodeUInt(messageData, ref currentPosition, SerialNumber);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, RefreshInterval);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, RetryInterval);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, ExpireInterval);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, NegativeCachingTTL);
		}
	}
}