#region Copyright and License
// Copyright 2010..2017 Alexander Reinert
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
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   <para>Parsed instance of the textual representation of a SenderID record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4406">RFC 4406</see>
	///   </para>
	/// </summary>
	public class SenderIdRecord : SpfRecordBase
	{
		private static readonly Regex _prefixRegex = new Regex(@"^v=spf((?<version>1)|(?<version>2)\.(?<minor>\d)/(?<scopes>(([a-z0-9]+,)*[a-z0-9]+)))$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

		/// <summary>
		///   Version of the SenderID record.
		/// </summary>
		public int Version { get; set; }

		/// <summary>
		///   Minor version of the SenderID record
		/// </summary>
		public int MinorVersion { get; set; }

		/// <summary>
		///   List of Scopes of the SenderID record
		/// </summary>
		public List<SenderIdScope> Scopes { get; set; }

		/// <summary>
		///   Returns the textual representation of the SenderID record
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			var res = new StringBuilder();

			if (Version == 1)
			    res.Append("v=spf1");
			else
			{
				res.Append("v=spf");
				res.Append(Version);
				res.Append(".");
				res.Append(MinorVersion);
				res.Append("/");
				res.Append(string.Join(",", Scopes.Where(s => s != SenderIdScope.Unknown).Select(s => EnumHelper<SenderIdScope>.ToString(s).ToLower())));
			}

			if (Terms != null && Terms.Count > 0)
			    foreach (var term in Terms)
			    {
			        var modifier = term as SpfModifier;
			        if (modifier == null || modifier.Type != SpfModifierType.Unknown)
			        {
			            res.Append(" ");
			            res.Append(term);
			        }
			    }

		    return res.ToString();
		}

		/// <summary>
		///   Checks, whether a given string starts with a correct SenderID prefix of a given scope
		/// </summary>
		/// <param name="s"> Textual representation to check </param>
		/// <param name="scope"> Scope, which should be matched </param>
		/// <returns> true in case of correct prefix </returns>
		public static bool IsSenderIdRecord(string s, SenderIdScope scope)
		{
			if (string.IsNullOrEmpty(s))
				return false;

			var terms = s.Split(new[] { ' ' }, 2);

			if (terms.Length < 2)
				return false;
            if (!TryParsePrefix(terms[0], out var version, out var minor, out var scopes)) return false;

		    if (version == 1 && (scope == SenderIdScope.MFrom || scope == SenderIdScope.Pra))
		        return true;
		    return scopes.Contains(scope);
		}

		private static bool TryParsePrefix(string prefix, out int version, out int minor, out List<SenderIdScope> scopes)
		{
			var match = _prefixRegex.Match(prefix);
			if (!match.Success)
			{
				version = 0;
				minor = 0;
				scopes = null;

				return false;
			}

			version = int.Parse(match.Groups["version"].Value);
			minor = int.Parse("0" + match.Groups["minor"].Value);
			scopes = match.Groups["scopes"].Value.Split(',').Select(t => EnumHelper<SenderIdScope>.Parse(t, true, SenderIdScope.Unknown)).ToList();

			return true;
		}

		/// <summary>
		///   Tries to parse the textual representation of a SenderID record
		/// </summary>
		/// <param name="s"> Textual representation to check </param>
		/// <param name="value"> Parsed SenderID record in case of successful parsing </param>
		/// <returns> true in case of successful parsing </returns>
		public static bool TryParse(string s, out SenderIdRecord value)
		{
			if (string.IsNullOrEmpty(s))
			{
				value = null;
				return false;
			}

			var terms = s.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

			if (terms.Length < 1)
			{
				value = null;
				return false;
			}
            if (!TryParsePrefix(terms[0], out var version, out var minor, out var scopes))
            {
                value = null;
                return false;
            }

            if (TryParseTerms(terms, out var parsedTerms))
            {
                value =
                    new SenderIdRecord
                    {
                        Version = version,
                        MinorVersion = minor,
                        Scopes = scopes,
                        Terms = parsedTerms
                    };
                return true;
            }

		    value = null;
		    return false;
		}
	}
}