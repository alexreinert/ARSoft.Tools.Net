using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Spf
{
	public enum SpfMechanismType
	{
		Unknown,

		All,
		Ip4,
		Ip6,
		A,
		Mx,
		Ptr,
		Exist,
		Include,
	}
}
