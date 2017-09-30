using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public enum RecordClass : byte
	{
		Invalid = 0,
		INet = 1,
		Chaos = 3,
		Hesiod = 4,
		None = 254,
		Any = 255
	}
}
