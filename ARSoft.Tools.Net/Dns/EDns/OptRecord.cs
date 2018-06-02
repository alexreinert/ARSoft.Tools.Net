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
using System.Linq;
using ARSoft.Tools.Net.Dns.DnsRecord;

namespace ARSoft.Tools.Net.Dns.EDns
{
    /// <inheritdoc />
    /// <summary>
    ///     <para>OPT record</para>
    ///     <para>
    ///         Defined in
    ///         <see cref="!:http://tools.ietf.org/html/rfc2671">RFC 2671</see>
    ///     </para>
    /// </summary>
    public class OptRecord : DnsRecordBase
    {
        /// <summary>
        ///     Creates a new instance of the OptRecord
        /// </summary>
        public OptRecord()
            : base(DomainName.Root, RecordType.Opt, (RecordClass) 512, 0)
        {
            UdpPayloadSize = 4096;
            Options = new List<EDnsOptionBase>();
        }

        /// <summary>
        ///     Gets or set the sender's UDP payload size
        /// </summary>
        public ushort UdpPayloadSize
        {
            get => (ushort) RecordClass;
            set => RecordClass = (RecordClass) value;
        }

        /// <summary>
        ///     Gets or sets the high bits of return code (EXTENDED-RCODE)
        /// </summary>
        public ReturnCode ExtendedReturnCode
        {
            get => (ReturnCode) ((TimeToLive & 0xff000000) >> 20);
            set
            {
                var clearedTtl = TimeToLive & 0x00ffffff;
                TimeToLive = clearedTtl | (int) value << 20;
            }
        }

        /// <summary>
        ///     Gets or set the EDNS version
        /// </summary>
        public byte Version
        {
            get => (byte) ((TimeToLive & 0x00ff0000) >> 16);
            set
            {
                var clearedTtl = (int) ((uint) TimeToLive & 0xff00ffff);
                TimeToLive = clearedTtl | value << 16;
            }
        }

        /// <summary>
        ///     <para>Gets or sets the DNSSEC OK (DO) flag</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc4035">RFC 4035</see>
        ///         and
        ///         <see cref="!:http://tools.ietf.org/html/rfc3225">RFC 3225</see>
        ///     </para>
        /// </summary>
        public bool IsDnsSecOk
        {
            get => (TimeToLive & 0x8000) != 0;
            set
            {
                if (value)
                    TimeToLive |= 0x8000;
                else
                    TimeToLive &= 0x7fff;
            }
        }

        /// <summary>
        ///     Gets or set additional EDNS options
        /// </summary>
        public List<EDnsOptionBase> Options { get; private set; }

        protected internal override int MaximumRecordDataLength
        {
            get
            {
                if (Options == null || Options.Count == 0)
                    return 0;
                return Options.Sum(option => option.DataLength + 4);
            }
        }

        internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
        {
            var endPosition = startPosition + length;

            Options = new List<EDnsOptionBase>();
            while (startPosition < endPosition)
            {
                var type = (EDnsOptionType) DnsMessageBase.ParseUShort(resultData, ref startPosition);
                var dataLength = DnsMessageBase.ParseUShort(resultData, ref startPosition);

                EDnsOptionBase option;

                switch (type)
                {
                    case EDnsOptionType.LongLivedQuery:
                        option = new LongLivedQueryOption();
                        break;

                    case EDnsOptionType.UpdateLease:
                        option = new UpdateLeaseOption();
                        break;

                    case EDnsOptionType.NsId:
                        option = new NsIdOption();
                        break;

                    case EDnsOptionType.Owner:
                        option = new OwnerOption();
                        break;

                    case EDnsOptionType.DnssecAlgorithmUnderstood:
                        option = new DnssecAlgorithmUnderstoodOption();
                        break;

                    case EDnsOptionType.DsHashUnderstood:
                        option = new DsHashUnderstoodOption();
                        break;

                    case EDnsOptionType.Nsec3HashUnderstood:
                        option = new Nsec3HashUnderstoodOption();
                        break;

                    case EDnsOptionType.ClientSubnet:
                        option = new ClientSubnetOption();
                        break;

                    case EDnsOptionType.Expire:
                        option = new ExpireOption();
                        break;

                    case EDnsOptionType.Cookie:
                        option = new CookieOption();
                        break;

                    default:
                        option = new UnknownOption(type);
                        break;
                }

                option.ParseData(resultData, startPosition, dataLength);
                Options.Add(option);
                startPosition += dataLength;
            }
        }

        internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        ///     Returns the textual representation of the OptRecord
        /// </summary>
        /// <returns> The textual representation </returns>
        public override string ToString() => RecordDataToString();

        internal override string RecordDataToString()
        {
            var flags = IsDnsSecOk ? "DO" : "";
            return $"; EDNS version: {Version}; flags: {flags}; udp: {UdpPayloadSize}";
        }


        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition,
            Dictionary<DomainName, ushort> domainNames, bool useCanonical)
        {
            if (Options != null && Options.Count != 0)
                foreach (var option in Options)
                {
                    DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) option.Type);
                    DnsMessageBase.EncodeUShort(messageData, ref currentPosition, option.DataLength);
                    option.EncodeData(messageData, ref currentPosition);
                }
        }
    }
}