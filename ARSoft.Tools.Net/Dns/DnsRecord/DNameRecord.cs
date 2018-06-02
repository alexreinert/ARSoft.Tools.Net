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
    ///     <para>DNS Name Redirection record</para>
    ///     <para>
    ///         Defined in
    ///         <see cref="!:http://tools.ietf.org/html/rfc6672">RFC 6672</see>
    ///     </para>
    /// </summary>
    public class DNameRecord : DnsRecordBase
    {
        internal DNameRecord()
        {
        }

        /// <summary>
        ///     Creates a new instance of the DNameRecord class
        /// </summary>
        /// <param name="name"> Name of the record </param>
        /// <param name="timeToLive"> Seconds the record should be cached at most </param>
        /// <param name="target"> Target of the redirection </param>
        public DNameRecord(DomainName name, int timeToLive, DomainName target)
            : base(name, RecordType.DName, RecordClass.INet, timeToLive) =>
            Target = target ?? DomainName.Root;

        /// <summary>
        ///     Target of the redirection
        /// </summary>
        public DomainName Target { get; private set; }

        protected internal override int MaximumRecordDataLength => Target.MaximumRecordDataLength + 2;

        internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
        {
            Target = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
        }

        internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
        {
            if (stringRepresentation.Length != 1)
                throw new FormatException();

            Target = ParseDomainName(origin, stringRepresentation[0]);
        }

        internal override string RecordDataToString() => Target.ToString();


        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition,
            Dictionary<DomainName, ushort> domainNames, bool useCanonical)
        {
            DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Target, null, useCanonical);
        }
    }
}