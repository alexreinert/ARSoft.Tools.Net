#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
	///   Type of record
	/// </summary>
	public enum RecordType : ushort
	{
		/// <summary>
		///   Invalid record type
		/// </summary>
		Invalid = 0,

		/// <summary>
		///   <para>Host address</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		A = 1,

		/// <summary>
		///   <para>Authoritatitve name server</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Ns = 2,

		/// <summary>
		///   <para>Mail destination</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		[Obsolete] Md = 3,

		/// <summary>
		///   <para>Mail forwarder</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		[Obsolete] Mf = 4,

		/// <summary>
		///   <para>Canonical name for an alias</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		CName = 5,

		/// <summary>
		///   <para>Start of zone of authority</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Soa = 6,

		/// <summary>
		///   <para>Mailbox domain name</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///     - Experimental
		///   </para>
		/// </summary>
		Mb = 7, // not supported yet

		/// <summary>
		///   <para>Mail group member</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///     - Experimental
		///   </para>
		/// </summary>
		Mg = 8, // not supported yet

		/// <summary>
		///   <para>Mail rename domain name</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///     - Experimental
		///   </para>
		/// </summary>
		Mr = 9, // not supported yet

		/// <summary>
		///   <para>Null record</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///     - Experimental
		///   </para>
		/// </summary>
		Null = 10, // not supported yet

		/// <summary>
		///   <para>Well known services</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Wks = 11,

		/// <summary>
		///   <para>Domain name pointer</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Ptr = 12,

		/// <summary>
		///   <para>Host information</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		HInfo = 13,

		/// <summary>
		///   <para>Mailbox or mail list information</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		MInfo = 14, // not supported yet

		/// <summary>
		///   <para>Mail exchange</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Mx = 15,

		/// <summary>
		///   <para>Text strings</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Txt = 16,

		/// <summary>
		///   <para>Responsible person</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>.
		///   </para>
		/// </summary>
		Rp = 17,

		/// <summary>
		///   <para>AFS data base location</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc5864.html">RFC 5864</a>.
		///   </para>
		/// </summary>
		Afsdb = 18,

		/// <summary>
		///   <para>X.25 PSDN address</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>.
		///   </para>
		/// </summary>
		X25 = 19,

		/// <summary>
		///   <para>ISDN address</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>.
		///   </para>
		/// </summary>
		Isdn = 20,

		/// <summary>
		///   <para>Route through</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1183.html">RFC 1183</a>.
		///   </para>
		/// </summary>
		Rt = 21,

		/// <summary>
		///   <para>NSAP address, NSAP style A record</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1706.html">RFC 1706</a>.
		///   </para>
		/// </summary>
		Nsap = 22,

		/// <summary>
		///   <para>Domain name pointer, NSAP style</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1348.html">RFC 1348</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc1637.html">RFC 1637</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc1706.html">RFC 1706</a>.
		///   </para>
		/// </summary>
		NsapPtr = 23, // not supported yet

		/// <summary>
		///   <para>Security signature</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc2931.html">RFC 2931</a>.
		///   </para>
		/// </summary>
		Sig = 24,

		/// <summary>
		///   <para>Security Key</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc2930.html">RFC 2930</a>.
		///   </para>
		/// </summary>
		Key = 25,

		/// <summary>
		///   <para>X.400 mail mapping information</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2163.html">RFC 2163</a>.
		///   </para>
		/// </summary>
		Px = 26,

		/// <summary>
		///   <para>Geographical position</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1712.html">RFC 1712</a>.
		///   </para>
		/// </summary>
		GPos = 27,

		/// <summary>
		///   <para>IPv6 address</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3596.html">RFC 3596</a>.
		///   </para>
		/// </summary>
		Aaaa = 28,

		/// <summary>
		///   <para>Location information</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1876.html">RFC 1876</a>.
		///   </para>
		/// </summary>
		Loc = 29,

		/// <summary>
		///   <para>Next domain</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
		///   </para>
		/// </summary>
		[Obsolete] Nxt = 30,

		/// <summary>
		///   <para>Endpoint identifier</para>
		///   <para>Defined by Michael Patton, &lt;map@bbn.com&gt;, June 1995</para>
		/// </summary>
		Eid = 31, // not supported yet

		/// <summary>
		///   <para>Nimrod locator</para>
		///   <para>Defined by Michael Patton, &lt;map@bbn.com&gt;, June 1995</para>
		/// </summary>
		NimLoc = 32, // not supported yet

		/// <summary>
		///   <para>Server selector</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2782.html">RFC 2782</a>.
		///   </para>
		/// </summary>
		Srv = 33,

		/// <summary>
		///   <para>ATM address</para>
		///   <para>
		///     Defined in
		///     <a href="http://broadband-forum.org/ftp/pub/approved-specs/af-saa-0069.000.pdf">
		///       ATM Forum Technical Committee, "ATM Name System, V2.0"
		///     </a>
		///   </para>
		/// </summary>
		AtmA = 34, // not supported yet

		/// <summary>
		///   <para>Naming authority pointer</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2915.html">RFC 2915</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc2168.html">RFC 2168</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3403.html">RFC 3403</a>.
		///   </para>
		/// </summary>
		Naptr = 35,

		/// <summary>
		///   <para>Key exchanger</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2230.html">RFC 2230</a>.
		///   </para>
		/// </summary>
		Kx = 36,

		/// <summary>
		///   <para>Certificate storage</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4398.html">RFC 4398</a>.
		///   </para>
		/// </summary>
		Cert = 37,

		/// <summary>
		///   <para>A6</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3226.html">RFC 3226</a>
		///     ,
		///     <a href="https://www.rfc-editor.org/rfc/rfc2874.html">RFC 2874</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc2874.html">RFC 2874</a>.
		///     - Experimental
		///   </para>
		/// </summary>
		[Obsolete] A6 = 38,

		/// <summary>
		///   <para>DNS Name Redirection</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6672.html">RFC 6672</a>.
		///   </para>
		/// </summary>
		DName = 39,

		/// <summary>
		///   <para>SINK</para>
		///   <para>Defined by Donald E. Eastlake, III &lt;d3e3e3@gmail.com&gt;, January 1995, November 1997</para>
		/// </summary>
		Sink = 40, // not supported yet

		/// <summary>
		///   <para>OPT</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6891.html">RFC 6891</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3658.html">RFC 3658</a>.
		///   </para>
		/// </summary>
		Opt = 41,

		/// <summary>
		///   <para>Address prefixes</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3123.html">RFC 3123</a>.
		///   </para>
		/// </summary>
		Apl = 42,

		/// <summary>
		///   <para>Delegation signer</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3658.html">RFC 3658</a>.
		///   </para>
		/// </summary>
		Ds = 43,

		/// <summary>
		///   <para>SSH key fingerprint</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4255.html">RFC 4255</a>.
		///   </para>
		/// </summary>
		SshFp = 44,

		/// <summary>
		///   <para>IPsec key storage</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
		///   </para>
		/// </summary>
		IpSecKey = 45,

		/// <summary>
		///   <para>Record signature</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>.
		///   </para>
		/// </summary>
		RrSig = 46,

		/// <summary>
		///   <para>Next owner</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>.
		///   </para>
		/// </summary>
		NSec = 47,

		/// <summary>
		///   <para>DNS Key</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>.
		///   </para>
		/// </summary>
		DnsKey = 48,

		/// <summary>
		///   <para>Dynamic Host Configuration Protocol (DHCP) Information</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4701.html">RFC 4701</a>.
		///   </para>
		/// </summary>
		Dhcid = 49,

		/// <summary>
		///   <para>Hashed next owner</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>.
		///   </para>
		/// </summary>
		NSec3 = 50,

		/// <summary>
		///   <para>Hashed next owner parameter</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>.
		///   </para>
		/// </summary>
		NSec3Param = 51,

		/// <summary>
		///   <para>TLSA</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
		///   </para>
		/// </summary>
		Tlsa = 52,

		/// <summary>
		///   <para>Host identity protocol</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5205.html">RFC 5205</a>.
		///   </para>
		/// </summary>
		Hip = 55,

		/// <summary>
		///   <para>NINFO</para>
		///   <para>Defined by Jim Reid, &lt;jim@telnic.org&gt;, 21 January 2008</para>
		/// </summary>
		NInfo = 56, // not supported yet

		/// <summary>
		///   <para>RKEY</para>
		///   <para>Defined by Jim Reid, &lt;jim@telnic.org&gt;, 21 January 2008</para>
		/// </summary>
		RKey = 57, // not supported yet

		/// <summary>
		///   <para>Trust anchor link</para>
		///   <para>Defined by Wouter Wijngaards, &lt;wouter@nlnetlabs.nl&gt;, 2010-02-17</para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		TALink = 58, // not supported yet

		/// <summary>
		///   <para>Child DS</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7344.html">RFC 7344</a>.
		///   </para>
		/// </summary>
		CDs = 59,

		/// <summary>
		///   <para>Child DnsKey</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7344.html">RFC 7344</a>.
		///   </para>
		/// </summary>
		CDnsKey = 60,

		/// <summary>
		///   <para>OpenPGP Key</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7929.html">RFC 7929</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		OpenPGPKey = 61,

		/// <summary>
		///   <para>Child-to-Parent Synchronization</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7477.html">RFC 7477</a>.
		///   </para>
		/// </summary>
		CSync = 62,

		/// <summary>
		///   <para>Sender Policy Framework</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4408.html">RFC 4408</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc7208.html">RFC 7208</a>.
		///   </para>
		/// </summary>
		[Obsolete] Spf = 99,

		/// <summary>
		///   <para>UINFO</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		UInfo = 100, // not supported yet

		/// <summary>
		///   <para>UID</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		UId = 101, // not supported yet

		/// <summary>
		///   <para>GID</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		Gid = 102, // not supported yet

		/// <summary>
		///   <para>UNSPEC</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		Unspec = 103, // not supported yet

		/// <summary>
		///   <para>NID</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6742.html">RFC 6742</a>.
		///   </para>
		/// </summary>
		NId = 104,

		/// <summary>
		///   <para>L32</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6742.html">RFC 6742</a>.
		///   </para>
		/// </summary>
		L32 = 105,

		/// <summary>
		///   <para>L64</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6742.html">RFC 6742</a>.
		///   </para>
		/// </summary>
		L64 = 106,

		/// <summary>
		///   <para>LP</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6742.html">RFC 6742</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		LP = 107,

		/// <summary>
		///   <para>EUI-48 address</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7043.html">RFC 7043</a>.
		///   </para>
		/// </summary>
		Eui48 = 108,

		/// <summary>
		///   <para>EUI-64 address</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7043.html">RFC 7043</a>.
		///   </para>
		/// </summary>
		Eui64 = 109,

		/// <summary>
		///   <para>Transaction key</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2930.html">RFC 2930</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		TKey = 249,

		/// <summary>
		///   <para>Transaction signature</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2845.html">RFC 2845</a>,
		///     <a href="https://www.rfc-editor.org/rfc/rfc4635.html">RFC 4635</a>
		///     and <a href="https://www.rfc-editor.org/rfc/rfc8945.html">RFC 8945</a>
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		TSig = 250,

		/// <summary>
		///   <para>Incremental zone transfer</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1995.html">RFC 1995</a>.
		///   </para>
		/// </summary>
		Ixfr = 251,

		/// <summary>
		///   <para>Request transfer of entire zone</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc5936.html">RFC 5936</a>.
		///   </para>
		/// </summary>
		Axfr = 252,

		/// <summary>
		///   <para>Request mailbox related recors</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		MailB = 253,

		/// <summary>
		///   <para>Request of mail agent records</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		[Obsolete] MailA = 254,

		/// <summary>
		///   <para>Request of all records</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Any = 255,

		/// <summary>
		///   <para>Uniform Resource Identifier</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc7553.html">RFC 7553</a>.
		///   </para>
		/// </summary>
		Uri = 256,

		/// <summary>
		///   <para>Certification authority authorization</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6844.html">RFC 6844</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		CAA = 257,

		/// <summary>
		///   <para>DNSSEC trust authorities</para>
		///   <para>Defined by Sam Weiler, &lt;weiler+iana@tislabs.com&gt;</para>
		/// </summary>
		Ta = 32768, // not supported yet

		/// <summary>
		///   <para>DNSSEC lookaside validation</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4431.html">RFC 4431</a>.
		///   </para>
		/// </summary>
		Dlv = 32769,
	}

	internal static class RecordTypeHelper
	{
		public static string ToShortString(this RecordType recordType)
		{
			string? res;
			if (!EnumHelper<RecordType>.Names.TryGetValue(recordType, out res))
			{
				return "TYPE" + (int) recordType;
			}

			return res.ToUpper();
		}

		public static bool TryParseShortString(string s, out RecordType recordType)
		{
			if (String.IsNullOrEmpty(s))
			{
				recordType = RecordType.Invalid;
				return false;
			}

			if (EnumHelper<RecordType>.TryParse(s, true, out recordType))
				return true;

			if (s.StartsWith("TYPE", StringComparison.InvariantCultureIgnoreCase))
			{
				ushort classValue;
				if (UInt16.TryParse(s.Substring(4), out classValue))
				{
					recordType = (RecordType) classValue;
					return true;
				}
			}

			recordType = RecordType.Invalid;
			return false;
		}

		public static RecordType ParseShortString(string s)
		{
			if (String.IsNullOrEmpty(s))
				throw new ArgumentOutOfRangeException(nameof(s));

			RecordType recordType;
			if (EnumHelper<RecordType>.TryParse(s, true, out recordType))
				return recordType;

			if (s.StartsWith("TYPE", StringComparison.InvariantCultureIgnoreCase))
			{
				ushort classValue;
				if (UInt16.TryParse(s.Substring(4), out classValue))
					return (RecordType) classValue;
			}

			throw new ArgumentOutOfRangeException(nameof(s));
		}
	}
}