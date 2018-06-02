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
using System.Linq;

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///     <para>EUI48</para>
    ///     <para>
    ///         Defined in
    ///         <see cref="!:http://tools.ietf.org/html/rfc7043">RFC 7043</see>
    ///     </para>
    /// </summary>
    public class Eui48Record : DnsRecordBase
    {
        internal Eui48Record()
        {
        }

        /// <summary>
        ///     Creates a new instance of the Eui48Record class
        /// </summary>
        /// <param name="name"> Domain name of the host </param>
        /// <param name="timeToLive"> Seconds the record should be cached at most </param>
        /// <param name="address"> The EUI48 address</param>
        public Eui48Record(DomainName name, int timeToLive, byte[] address)
            : base(name, RecordType.Eui48, RecordClass.INet, timeToLive) =>
            Address = address ?? new byte[6];

        /// <summary>
        ///     IP address of the host
        /// </summary>
        public byte[] Address { get; private set; }

        protected internal override int MaximumRecordDataLength => 6;

        internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
        {
            Address = DnsMessageBase.ParseByteData(resultData, ref startPosition, 6);
        }

        internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
        {
            if (stringRepresentation.Length != 1)
                throw new NotSupportedException();

            Address = stringRepresentation[0].Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();

            if (Address.Length != 6)
                throw new NotSupportedException();
        }

        internal override string RecordDataToString()
        {
            return string.Join("-", Address.Select(x => x.ToString("x2")).ToArray());
        }


        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition,
            Dictionary<DomainName, ushort> domainNames, bool useCanonical)
        {
            DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Address);
        }
    }
}