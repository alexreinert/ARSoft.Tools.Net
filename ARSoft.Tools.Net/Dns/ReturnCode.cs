using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public enum ReturnCode : ushort
	{
		NoError = 0,
		FormatError = 1,
		ServerFailure = 2,
		NxDomain = 3,
		NotImplemented = 4,
		Refused = 5,

		YXDomain = 6,
		YXRRSet = 7,
		NXRRSet = 8,
		NotAuthoritive = 9,
		NotZone = 10,

		BadVersion = 16,
		BadSig = 16,
		BadKey = 17,
		BadTime = 18,
		BadMode = 19,
		BadName = 20,
		BadAlg = 21,
		BadTrunc = 22,
	}
}
