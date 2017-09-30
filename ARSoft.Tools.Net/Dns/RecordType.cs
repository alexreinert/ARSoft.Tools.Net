#region Copyright and License
// Copyright 2010..11 Alexander Reinert
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
	public enum RecordType : ushort
	{
		Invalid = 0,

		A = 1, // RFC1035
		Ns = 2, // RFC1035
		Md = 3, // RFC1035 - Obsolete
		Mf = 4, // RFC1035 - Obsolete
		CName = 5, // RFC1035
		Soa = 6, // RFC1035
		Mb = 7, // RFC1035 - Experimental
		Mg = 8, // RFC1035 - Experimental
		Mr = 9, // RFC1035 - Experimental
		Null = 10, // RFC1035 - Experimental
		Wks = 11, // RFC1035
		Ptr = 12, // RFC1035
		HInfo = 13, // RFC1035
		MInfo = 14, // RFC1035 - Experimental
		Mx = 15, // RFC1035
		Txt = 16, // RFC1035
		Rp = 17, // RFC1183
		Afsdb = 18, // RFC1183
		X25 = 19, // RFC1183
		Isdn = 20, // RFC1183
		Rt = 21, // RFC1183
		Nsap = 22, // RFC1706
		NsapPrt = 23, // RFC1348 - Obsolete
		Sig = 24, // RFC2931
		Key = 25, // RFC2930
		Px = 26, // RFC2163
		GPos = 27, // RFC1712
		Aaaa = 28, // RFC3596
		Loc = 29, // RFC1876
		Nxt = 30, // RFC3755 - Obsolete
		Eid = 31, // Patton - not supported yet
		NimLoc = 32, // Patton - not supported yet
		Srv = 33, // RFC2782
		AtmA = 34, // ATMDOC - not supported yet
		Naptr = 35, // RFC2915
		Kx = 36, // RFC2230
		Cert = 37, // RFC4398
		A6 = 38, // RFC3226 - Experimental
		DName = 39, // RFC2672
		Sink = 40, // Eastlake - not supported yet
		Opt = 41, // RFC2671
		Apl = 42, // RFC3123
		Ds = 43, // RFC4034
		SshFp = 44, // RFC4255
		IpSecKey = 45, // RFC4025
		RrSig = 46, // RFC4034
		NSec = 47, // RFC4034
		DnsKey = 48, // RFC4034
		DhcpI = 49, // RFC4701
		NSec3 = 50, // RFC5155
		NSec3Param = 51, // RFC5155
		Hip = 55, // RFC5205
		NInfo = 56, // Reid - not supported yet
		RKey = 57, // Reid - not supported yet
		TALink = 58, // Wijngaards - not supported yet
		Spf = 99, // RFC4408
		UInfo = 100, // IANA-Reserved
		UId = 101, // IANA-Reserved
		Gid = 102, // IANA-Reserved
		Unspec = 103, // IANA-Reserved
		TKey = 249, // RFC2930
		TSig = 250, // RFC2845
		Ixfr = 251, // RFC1995
		Axfr = 252, // RFC1035
		MailB = 253, // RFC1035
		MailA = 254, // RFC1035 - Obsolete
		Any = 255, // RFC1035
		Ta = 32768, // Weiler - not supported yet
		Dlv = 32769, // RFC4431
	}
}