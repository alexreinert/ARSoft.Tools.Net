#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
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
using System.Text;
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net
{
	internal static class StringExtensions
	{
		private static readonly Regex _fromStringRepresentationRegex = new Regex(@"\\(?<key>([^0-9]|\d\d\d))", RegexOptions.Compiled);

		internal static string FromMasterfileLabelRepresentation(this string s)
		{
			if (s == null)
				return null;

			return _fromStringRepresentationRegex.Replace(s, k =>
			{
				string key = k.Groups["key"].Value;

				if (key == "#")
				{
					return @"\#";
				}
				else if (key.Length == 3)
				{
					return new String((char) Byte.Parse(key), 1);
				}
				else
				{
					return key;
				}
			});
		}

		internal static string ToMasterfileLabelRepresentation(this string s, bool encodeDots = false)
		{
			if (s == null)
				return null;

			StringBuilder sb = new StringBuilder();

			for (int i = 0; i < s.Length; i++)
			{
				char c = s[i];

				if ((c < 32) || (c > 126))
				{
					sb.Append(@"\" + ((int) c).ToString("000"));
				}
				else if (c == '"')
				{
					sb.Append(@"\""");
				}
				else if (c == '\\')
				{
					sb.Append(@"\\");
				}
				else if ((c == '.') && encodeDots)
				{
					sb.Append(@"\.");
				}
				else
				{
					sb.Append(c);
				}
			}

			return sb.ToString();
		}

		private static readonly Random _random = new Random();
		// ReSharper disable once InconsistentNaming
		internal static string Add0x20Bits(this string s)
		{
			char[] res = new char[s.Length];

			for (int i = 0; i < s.Length; i++)
			{
				bool isLower = _random.Next() > 0x3ffffff;

				char current = s[i];

				if (!isLower && current >= 'A' && current <= 'Z')
				{
					current = (char) (current + 0x20);
				}
				else if (isLower && current >= 'a' && current <= 'z')
				{
					current = (char) (current - 0x20);
				}

				res[i] = current;
			}

			return new string(res);
		}
	}
}