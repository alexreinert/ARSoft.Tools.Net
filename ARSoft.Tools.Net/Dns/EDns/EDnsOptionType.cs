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


namespace ARSoft.Tools.Net.Dns.EDns
{
    /// <summary>
    ///     ENDS Option types
    /// </summary>
    public enum EDnsOptionType : ushort
    {
        /// <summary>
        ///     <para>Update Lease</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://files.dns-sd.org/draft-sekar-dns-llq.txt">draft-sekar-dns-llq</see>
        ///     </para>
        /// </summary>
        LongLivedQuery = 1,

        /// <summary>
        ///     <para>Update Lease</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://files.dns-sd.org/draft-sekar-dns-ul.txt">draft-sekar-dns-ul</see>
        ///     </para>
        /// </summary>
        UpdateLease = 2,

        /// <summary>
        ///     <para>Name server ID</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc5001">RFC 5001</see>
        ///     </para>
        /// </summary>
        NsId = 3,

        /// <summary>
        ///     <para>Owner</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/draft-cheshire-edns0-owner-option">draft-cheshire-edns0-owner-option</see>
        ///     </para>
        /// </summary>
        Owner = 4,

        /// <summary>
        ///     <para>DNSSEC Algorithm Understood</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
        ///     </para>
        /// </summary>
        DnssecAlgorithmUnderstood = 5,

        /// <summary>
        ///     <para>DS Hash Understood</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
        ///     </para>
        /// </summary>
        DsHashUnderstood = 6,

        /// <summary>
        ///     <para>NSEC3 Hash Understood</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
        ///     </para>
        /// </summary>
        Nsec3HashUnderstood = 7,

        /// <summary>
        ///     <para>ClientSubnet</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet">draft-vandergaast-edns-client-subnet</see>
        ///     </para>
        /// </summary>
        ClientSubnet = 8,

        /// <summary>
        ///     <para>Expire EDNS Option</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/rfc7314">RFC 7314</see>
        ///     </para>
        /// </summary>
        Expire = 9,

        /// <summary>
        ///     <para>Cookie Option</para>
        ///     <para>
        ///         Defined in
        ///         <see cref="!:http://tools.ietf.org/html/draft-ietf-dnsop-cookies">draft-ietf-dnsop-cookies</see>
        ///     </para>
        /// </summary>
        Cookie = 10
    }
}