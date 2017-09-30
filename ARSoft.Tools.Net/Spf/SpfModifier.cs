using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Spf
{
	public class SpfModifier : SpfTerm
	{
		public SpfModifierType Type { get; set; }
		public string Domain { get; set; }

		public override string ToString()
		{
			StringBuilder res = new StringBuilder();

			res.Append(EnumHelper<SpfModifierType>.ToString(Type).ToLower());
			res.Append("=");
			res.Append(Domain);

			return res.ToString();
		}
	}
}
