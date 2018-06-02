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

using System;
using System.Collections.Generic;

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///     <para>Canonical name for an alias</para>
    ///     <para>
    ///         Defined in
    ///         <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
    ///     </para>
    /// </summary>
    public class CNameRecord : DnsRecordBase
    {
        internal CNameRecord()
        {
        }

        /// <summary>
        ///     Creates a new instance of the CNameRecord class
        /// </summary>
        /// <param name="name"> Domain name the host </param>
        /// <param name="timeToLive"> Seconds the record should be cached at most </param>
        /// <param name="canonicalName"> Canocical name for the alias of the host </param>
        public CNameRecord(DomainName name, int timeToLive, DomainName canonicalName)
            : base(name, RecordType.CName, RecordClass.INet, timeToLive) =>
            CanonicalName = canonicalName ?? DomainName.Root;

        /// <summary>
        ///     Canonical name
        /// </summary>
        public DomainName CanonicalName { get; private set; }

        protected internal override int MaximumRecordDataLength => CanonicalName.MaximumRecordDataLength + 2;

        internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
        {
            CanonicalName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
        }

        internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
        {
            if (stringRepresentation.Length != 1)
                throw new FormatException();

            CanonicalName = ParseDomainName(origin, stringRepresentation[0]);
        }

        internal override string RecordDataToString() => CanonicalName.ToString();


        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition,
            Dictionary<DomainName, ushort> domainNames, bool useCanonical)
        {
            DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, CanonicalName, domainNames,
                useCanonical);
        }
    }
}