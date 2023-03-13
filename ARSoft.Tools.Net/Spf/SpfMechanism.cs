#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
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

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   Represents a single mechanism term in a SPF record
	/// </summary>
	public class SpfMechanism : SpfTerm
	{
		/// <summary>
		///   Qualifier of the mechanism
		/// </summary>
		public SpfQualifier Qualifier { get; }

		/// <summary>
		///   Type of the mechanism
		/// </summary>
		public SpfMechanismType Type { get; }

		/// <summary>
		///   Domain part of the mechanism
		/// </summary>
		public string? Domain { get; }

		/// <summary>
		///   IPv4 prefix of the mechanism
		/// </summary>
		public int? Prefix { get; }

		/// <summary>
		///   IPv6 prefix of the mechanism
		/// </summary>
		public int? Prefix6 { get; }

		/// <summary>
		///   Creates a new instance of the SpfMechanism
		/// </summary>
		/// <param name="qualifier">Qualifier of the mechanism</param>
		/// <param name="type">Type of the mechanism</param>
		/// <param name="domain">Domain part of the mechanism</param>
		/// <param name="prefix">IPv4 prefix of the mechanism</param>
		/// <param name="prefix6">IPv6 prefix of the mechanism</param>
		public SpfMechanism(SpfQualifier qualifier, SpfMechanismType type, string? domain = null, int? prefix = null, int? prefix6 = null)
		{
			Qualifier = qualifier;
			Type = type;
			Domain = domain;
			Prefix = prefix;
			Prefix6 = prefix6;
		}

		/// <summary>
		///   Returns the textual representation of a mechanism term
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			var res = new StringBuilder
			{
				Capacity = 0,
				Length = 0
			};

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