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
using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///     <para>IPsec key storage</para>
    ///     <para>
    ///         Defined in
    ///         <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
    ///     </para>
    /// </summary>
    public class IpSecKeyRecord : DnsRecordBase
    {
        /// <summary>
        ///     Algorithm of key
        /// </summary>
        public enum IpSecAlgorithm : byte
        {
            /// <summary>
            ///     None
            /// </summary>
            None = 0,

            /// <summary>
            ///     <para>RSA</para>
            ///     <para>
            ///         Defined in
            ///         <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
            ///     </para>
            /// </summary>
            Rsa = 1,

            /// <summary>
            ///     <para>DSA</para>
            ///     <para>
            ///         Defined in
            ///         <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
            ///     </para>
            /// </summary>
            Dsa = 2
        }

        /// <summary>
        ///     Type of gateway
        /// </summary>
        public enum IpSecGatewayType : byte
        {
            /// <summary>
            ///     None
            /// </summary>
            None = 0,

            /// <summary>
            ///     <para>Gateway is a IPv4 address</para>
            ///     <para>
            ///         Defined in
            ///         <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
            ///     </para>
            /// </summary>
            IpV4 = 1,

            /// <summary>
            ///     <para>Gateway is a IPv6 address</para>
            ///     <para>
            ///         Defined in
            ///         <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
            ///     </para>
            /// </summary>
            IpV6 = 2,

            /// <summary>
            ///     <para>Gateway is a domain name</para>
            ///     <para>
            ///         Defined in
            ///         <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
            ///     </para>
            /// </summary>
            Domain = 3
        }

        internal IpSecKeyRecord()
        {
        }

        /// <summary>
        ///     Creates a new instance of the IpSecKeyRecord class
        /// </summary>
        /// <param name="name"> Name of the record </param>
        /// <param name="timeToLive"> Seconds the record should be cached at most </param>
        /// <param name="precedence"> Precedence of the record </param>
        /// <param name="algorithm"> Algorithm of the key </param>
        /// <param name="gateway"> Address of the gateway </param>
        /// <param name="publicKey"> Binary data of the public key </param>
        public IpSecKeyRecord(DomainName name, int timeToLive, byte precedence, IpSecAlgorithm algorithm,
            DomainName gateway, byte[] publicKey)
            : base(name, RecordType.IpSecKey, RecordClass.INet, timeToLive)
        {
            Precedence = precedence;
            GatewayType = IpSecGatewayType.Domain;
            Algorithm = algorithm;
            Gateway = (gateway ?? DomainName.Root).ToString();
            PublicKey = publicKey ?? new byte[] { };
        }

        /// <summary>
        ///     Creates a new instance of the IpSecKeyRecord class
        /// </summary>
        /// <param name="name"> Name of the record </param>
        /// <param name="timeToLive"> Seconds the record should be cached at most </param>
        /// <param name="precedence"> Precedence of the record </param>
        /// <param name="algorithm"> Algorithm of the key </param>
        /// <param name="gateway"> Address of the gateway </param>
        /// <param name="publicKey"> Binary data of the public key </param>
        public IpSecKeyRecord(DomainName name, int timeToLive, byte precedence, IpSecAlgorithm algorithm,
            IPAddress gateway, byte[] publicKey)
            : base(name, RecordType.IpSecKey, RecordClass.INet, timeToLive)
        {
            Precedence = precedence;
            GatewayType = gateway.AddressFamily == AddressFamily.InterNetwork
                ? IpSecGatewayType.IpV4
                : IpSecGatewayType.IpV6;
            Algorithm = algorithm;
            Gateway = gateway.ToString();
            PublicKey = publicKey ?? new byte[] { };
        }

        /// <summary>
        ///     Precedence of the record
        /// </summary>
        public byte Precedence { get; private set; }

        /// <summary>
        ///     Type of gateway
        /// </summary>
        public IpSecGatewayType GatewayType { get; private set; }

        /// <summary>
        ///     Algorithm of the key
        /// </summary>
        public IpSecAlgorithm Algorithm { get; private set; }

        /// <summary>
        ///     Address of the gateway
        /// </summary>
        public string Gateway { get; private set; }

        /// <summary>
        ///     Binary data of the public key
        /// </summary>
        public byte[] PublicKey { get; private set; }

        protected internal override int MaximumRecordDataLength
        {
            get
            {
                var res = 3;
                switch (GatewayType)
                {
                    case IpSecGatewayType.IpV4:
                        res += 4;
                        break;
                    case IpSecGatewayType.IpV6:
                        res += 16;
                        break;
                    case IpSecGatewayType.Domain:
                        res += 2 + Gateway.Length;
                        break;
                }

                res += PublicKey.Length;
                return res;
            }
        }

        internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
        {
            var startPosition = currentPosition;

            Precedence = resultData[currentPosition++];
            GatewayType = (IpSecGatewayType) resultData[currentPosition++];
            Algorithm = (IpSecAlgorithm) resultData[currentPosition++];
            switch (GatewayType)
            {
                case IpSecGatewayType.None:
                    Gateway = string.Empty;
                    break;
                case IpSecGatewayType.IpV4:
                    Gateway = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 4))
                        .ToString();
                    break;
                case IpSecGatewayType.IpV6:
                    Gateway =
                        new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 16)).ToString();
                    break;
                case IpSecGatewayType.Domain:
                    Gateway = DnsMessageBase.ParseDomainName(resultData, ref currentPosition).ToString();
                    break;
            }

            PublicKey = DnsMessageBase.ParseByteData(resultData, ref currentPosition,
                length + startPosition - currentPosition);
        }

        internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
        {
            if (stringRepresentation.Length < 5)
                throw new FormatException();

            Precedence = byte.Parse(stringRepresentation[0]);
            GatewayType = (IpSecGatewayType) byte.Parse(stringRepresentation[1]);
            Algorithm = (IpSecAlgorithm) byte.Parse(stringRepresentation[2]);
            Gateway = stringRepresentation[3];
            PublicKey = string.Join(string.Empty, stringRepresentation.Skip(4)).FromBase64String();
        }

        internal override string RecordDataToString() =>
            Precedence
            + " " + (byte) GatewayType
            + " " + (byte) Algorithm
            + " " + GatewayToString()
            + " " + PublicKey.ToBase64String();

        private string GatewayToString()
        {
            switch (GatewayType)
            {
                case IpSecGatewayType.Domain:
                    return Gateway.ToMasterfileLabelRepresentation() + ".";

                case IpSecGatewayType.IpV4:
                case IpSecGatewayType.IpV6:
                    return Gateway;

                default:
                    return ".";
            }
        }


        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition,
            Dictionary<DomainName, ushort> domainNames, bool useCanonical)
        {
            messageData[currentPosition++] = Precedence;
            messageData[currentPosition++] = (byte) GatewayType;
            messageData[currentPosition++] = (byte) Algorithm;
            switch (GatewayType)
            {
                case IpSecGatewayType.IpV4:
                case IpSecGatewayType.IpV6:
                    var addressBuffer = IPAddress.Parse(Gateway).GetAddressBytes();
                    DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, addressBuffer);
                    break;
                case IpSecGatewayType.Domain:
                    DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition,
                        ParseDomainName(DomainName.Root, Gateway), null, false);
                    break;
            }

            DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
        }
    }
}