using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Spf
{
	public enum SpfQualifier
	{
		None,
		Pass,
		Fail,
		SoftFail,
		Neutral,
		TempError,
		PermError,
	}
}
