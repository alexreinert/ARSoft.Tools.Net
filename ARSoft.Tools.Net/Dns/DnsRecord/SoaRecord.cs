#region Copyright and License

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

using System.Collections.Generic;

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///     <para>Start of zone of authority record</para>
    ///     <para>
    ///         Defined in
    ///         <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
    ///     </para>
    /// </summary>
    public class SoaRecord : DnsRecordBase
    {
        internal SoaRecord()
        {
        }

        /// <summary>
        ///     Creates a new instance of the SoaRecord class
        /// </summary>
        /// <param name="name"> Name of the zone </param>
        /// <param name="timeToLive"> Seconds the record should be cached at most </param>
        /// <param name="masterName"> Hostname of the primary name server </param>
        /// <param name="responsibleName"> Mail address of the responsable person. The @ should be replaced by a dot. </param>
        /// <param name="serialNumber"> Serial number of the zone </param>
        /// <param name="refreshInterval"> Seconds before the zone should be refreshed </param>
        /// <param name="retryInterval"> Seconds that should be elapsed before retry of failed transfer </param>
        /// <param name="expireInterval"> Seconds that can elapse before the zone is no longer authorative </param>
        /// <param name="negativeCachingTtl">
        ///     <para>Seconds a negative answer could be cached</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc2308">RFC 2308</see>
        ///     </para>
        /// </param>
        // ReSharper disable once InconsistentNaming
        public SoaRecord(DomainName name, int timeToLive, DomainName masterName, DomainName responsibleName,
            uint serialNumber, int refreshInterval, int retryInterval, int expireInterval, int negativeCachingTtl)
            : base(name, RecordType.Soa, RecordClass.INet, timeToLive)
        {
            MasterName = masterName ?? DomainName.Root;
            ResponsibleName = responsibleName ?? DomainName.Root;
            SerialNumber = serialNumber;
            RefreshInterval = refreshInterval;
            RetryInterval = retryInterval;
            ExpireInterval = expireInterval;
            NegativeCachingTTL = negativeCachingTtl;
        }

        /// <summary>
        ///     Hostname of the primary name server
        /// </summary>
        public DomainName MasterName { get; private set; }

        /// <summary>
        ///     Mail address of the responsable person. The @ should be replaced by a dot.
        /// </summary>
        public DomainName ResponsibleName { get; private set; }

        /// <summary>
        ///     Serial number of the zone
        /// </summary>
        public uint SerialNumber { get; private set; }

        /// <summary>
        ///     Seconds before the zone should be refreshed
        /// </summary>
        public int RefreshInterval { get; private set; }

        /// <summary>
        ///     Seconds that should be elapsed before retry of failed transfer
        /// </summary>
        public int RetryInterval { get; private set; }

        /// <summary>
        ///     Seconds that can elapse before the zone is no longer authorative
        /// </summary>
        public int ExpireInterval { get; private set; }

        /// <summary>
        ///     <para>Seconds a negative answer could be cached</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc2308">RFC 2308</see>
        ///     </para>
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public int NegativeCachingTTL { get; private set; }

        protected internal override int MaximumRecordDataLength =>
            MasterName.MaximumRecordDataLength + ResponsibleName.MaximumRecordDataLength + 24;

        internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
        {
            MasterName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
            ResponsibleName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);

            SerialNumber = DnsMessageBase.ParseUInt(resultData, ref startPosition);
            RefreshInterval = DnsMessageBase.ParseInt(resultData, ref startPosition);
            RetryInterval = DnsMessageBase.ParseInt(resultData, ref startPosition);
            ExpireInterval = DnsMessageBase.ParseInt(resultData, ref startPosition);
            NegativeCachingTTL = DnsMessageBase.ParseInt(resultData, ref startPosition);
        }

        internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
        {
            MasterName = ParseDomainName(origin, stringRepresentation[0]);
            ResponsibleName = ParseDomainName(origin, stringRepresentation[1]);

            SerialNumber = uint.Parse(stringRepresentation[2]);
            RefreshInterval = int.Parse(stringRepresentation[3]);
            RetryInterval = int.Parse(stringRepresentation[4]);
            ExpireInterval = int.Parse(stringRepresentation[5]);
            NegativeCachingTTL = int.Parse(stringRepresentation[6]);
        }

        internal override string RecordDataToString() =>
            MasterName
            + " " + ResponsibleName
            + " " + SerialNumber
            + " " + RefreshInterval
            + " " + RetryInterval
            + " " + ExpireInterval
            + " " + NegativeCachingTTL;

        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition,
            Dictionary<DomainName, ushort> domainNames, bool useCanonical)
        {
            DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, MasterName, domainNames,
                useCanonical);
            DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, ResponsibleName, domainNames,
                useCanonical);
            DnsMessageBase.EncodeUInt(messageData, ref currentPosition, SerialNumber);
            DnsMessageBase.EncodeInt(messageData, ref currentPosition, RefreshInterval);
            DnsMessageBase.EncodeInt(messageData, ref currentPosition, RetryInterval);
            DnsMessageBase.EncodeInt(messageData, ref currentPosition, ExpireInterval);
            DnsMessageBase.EncodeInt(messageData, ref currentPosition, NegativeCachingTTL);
        }
    }
}