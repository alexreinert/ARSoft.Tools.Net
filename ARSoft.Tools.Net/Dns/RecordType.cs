using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public enum RecordType : uint
	{
		Invalid = 0,

		A = 1,
		Ns = 2,
		Md = 3, // Obsolete RFC973
		Mf = 4, // Obsolete RFC973
		CName = 5,
		Soa = 6,
		Mb = 7, // not supported yet
		Mg = 8, // not supported yet
		Mr = 9, // not supported yet
		Null = 10, // Obsolete RFC1035
		Wks = 11, // not supported yet
		Ptr = 12,
		HInfo = 13, // not supported yet
		MInfo = 14, // not supported yet
		Mx = 15,
		Txt = 16,
		Rp = 17, // not supported yet
		Afsdb = 18,
		X25 = 19, // not supported yet
		Isdn = 20, // not supported yet
		Rt = 21, // not supported yet
		Nsap = 22, // not supported yet
		NsapPrt = 23, // not supported yet
		Sig = 24, // !!! not supported yet
		Key = 25, // !!! not supported yet
		Px = 26, // not supported yet
		GPos = 27, // not supported yet
		Aaaa = 28,
		Loc = 29, // !!! not supported yet
		Nxt = 30,// Obsolete RFC3755
		Eid = 31, // not supported yet
		NimLoc = 32, // not supported yet
		Srv = 33,
		AtmA = 34, // not supported yet
		Naptr = 35,
		Kx = 36, // Obsolete RFC?
		Cert = 37, // !!! not supported yet
		A6 = 38, // not supported yet
		DName = 39,
		Sink = 40, // not supported yet
		Apl = 42, // not supported yet
		Ds = 43, // !!! not supported yet
		SshFp = 44, // !!! not supported yet
		IpSecKey = 45, // !!! not supported yet
		RrSig = 46, // !!! not supported yet
		NSec = 47, // !!! not supported yet
		DnsKey = 48, // !!! not supported yet
		DhcpI = 49, // !!! not supported yet
		NSec3 = 50, // !!! not supported yet
		NSec3Param = 51, // !!! not supported yet
		Hip = 55, // !!! not supported yet
		NInfo = 56, // not supported yet
		RKey = 57, // not supported yet
		Spf = 99,
		UInfo = 100, // IANA-Reserved
		UId = 101, // IANA-Reserved
		Gid = 102, // IANA-Reserved
		Unspec = 103, // IANA-Reserved
		MailB = 253, // not supported yet
		MailA = 254, // Obsolete RFC973
		Ta = 32768, // !!! not supported yet
		Dlv = 32769, // !!! not supported yet

		Opt = 41, // !!! not supported yet
		TKey = 249, // !!! not supported yet
		TSig = 250, // !!! not supported yet
		Ixfr = 251,
		Axfr = 252,

		Any = 255,
	}
}
