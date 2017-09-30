using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Spf
{
	public class SpfMechanism : SpfTerm
	{
		public SpfQualifier Qualifier { get; set; }
		public SpfMechanismType Type { get; set; }
		public string Domain { get; set; }
		public int? Prefix { get; set; }
		public int? Prefix6 { get; set; }

		public override string ToString()
		{
			StringBuilder res = new StringBuilder();

			switch (Qualifier)
			{
				case SpfQualifier.Fail:
					res.Append("-");
					break;
				case SpfQualifier.SoftFail:
					res.Append("~");
					break;
				case SpfQualifier.Neutral:
					res.Append("?");
					break;
			}

			res.Append(EnumHelper<SpfMechanismType>.ToString(Type).ToLower());

			if (!String.IsNullOrEmpty(Domain))
			{
				res.Append(":");
				res.Append(Domain);
			}

			if (Prefix.HasValue)
			{
				res.Append("/");
				res.Append(Prefix.Value);
			}

			if (Prefix6.HasValue)
			{
				res.Append("//");
				res.Append(Prefix6.Value);
			}

			return res.ToString();
		}
	}
}
