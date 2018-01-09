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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   ENDS Option types
	/// </summary>
	public enum EDnsOptionType : ushort
	{
		/// <summary>
		///   <para>Update Lease</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://files.dns-sd.org/draft-sekar-dns-llq.txt">draft-sekar-dns-llq</see>
		///   </para>
		/// </summary>
		LongLivedQuery = 1,

		/// <summary>
		///   <para>Update Lease</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://files.dns-sd.org/draft-sekar-dns-ul.txt">draft-sekar-dns-ul</see>
		///   </para>
		/// </summary>
		UpdateLease = 2,

		/// <summary>
		///   <para>Name server ID</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5001">RFC 5001</see>
		///   </para>
		/// </summary>
		NsId = 3,

		/// <summary>
		///   <para>Owner</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/draft-cheshire-edns0-owner-option">draft-cheshire-edns0-owner-option</see>
		///   </para>
		/// </summary>
		Owner = 4,

		/// <summary>
		///   <para>DNSSEC Algorithm Understood</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
		///   </para>
		/// </summary>
		DnssecAlgorithmUnderstood = 5,

		/// <summary>
		///   <para>DS Hash Understood</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
		///   </para>
		/// </summary>
		DsHashUnderstood = 6,

		/// <summary>
		///   <para>NSEC3 Hash Understood</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
		///   </para>
		/// </summary>
		Nsec3HashUnderstood = 7,

		/// <summary>
		///   <para>ClientSubnet</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet">draft-vandergaast-edns-client-subnet</see>
		///   </para>
		/// </summary>
		ClientSubnet = 8,

		/// <summary>
		///   <para>Expire EDNS Option</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc7314">RFC 7314</see>
		///   </para>
		/// </summary>
		Expire = 9,

		/// <summary>
		///   <para>Cookie Option</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/draft-ietf-dnsop-cookies">draft-ietf-dnsop-cookies</see>
		///   </para>
		/// </summary>
		Cookie = 10,

        /// <summary>
		///   <para>TCP keep alive option</para>
		///   <para>
		///     Defined in
		///     <see cref="!:https://tools.ietf.org/html/rfc7828">The edns-tcp-keepalive EDNS0 Option</see>
		///   </para>
		/// </summary>
		TcpKeepAlive = 11,

        /// <summary>
		///   <para>Padding option</para>
		///   <para>
		///     Defined in
		///     <see cref="!:https://tools.ietf.org/html/rfc7830">The EDNS(0) Padding Option</see>
		///   </para>
		/// </summary>
		Padding = 12,

        /// <summary>
		///   <para>Beginning of range reserved option for local/experimental use</para>
		///   <para>
		///     Defined in
		///     <see cref="!:https://tools.ietf.org/html/rfc6891">Extension Mechanisms for DNS (EDNS(0))</see>
		///   </para>
		/// </summary>
		LocalStart = 65001,

        /// <summary>
		///   <para>End of range reserved reserved option for local/experimental use</para>
		///   <para>
		///     Defined in
		///     <see cref="!:https://tools.ietf.org/html/rfc6891">Extension Mechanisms for DNS (EDNS(0))</see>
		///   </para>
		/// </summary>
		LocalEnd = 65534,
    }
}
