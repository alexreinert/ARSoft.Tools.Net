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

using Org.BouncyCastle.Utilities;
using System;
using System.Text;
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net
{
	internal static class StringExtensions
	{
		internal static int IndexOfWithQuoting(this string s, char value, int startIndex = 0)
		{
			var inQuote = false;

			for (var i = startIndex; i < s.Length; i++)
			{
				if (s[i] == '\\') // ignore escape char and escaped char
				{
					i++;
				}
				else if (!inQuote && s[i] == value)
				{
					return i;
				}
				else if (s[i] == '"')
				{
					inQuote = !inQuote;
				}
			}

			return -1;
		}

		internal static int IndexOfAnyWithEscaping(this string s, char[] values, int startIndex = 0)
		{
			for (var i = startIndex; i < s.Length; i++)
			{
				if (s[i] == '\\') // ignore escape char and escaped char
				{
					i++;
				}
				else if (values.Any(v => s[i] == v))
				{
					return i;
				}
			}

			return -1;
		}

		internal static string[] SplitWithQuoting(this string s, char[] separators, bool splitOnQuotes = false, bool removeEmptyEntries = false)
		{
			var res = new List<string>();
			var lastIndex = 0;
			bool inQuote = false;

			separators = separators.Append('"').ToArray();

			var nextIndex = s.IndexOfAnyWithEscaping(separators, lastIndex);
			while (nextIndex != -1)
			{
				if (s[nextIndex] == '"')
				{
					inQuote = !inQuote;

					if (!splitOnQuotes)
					{
						nextIndex = s.IndexOfAnyWithEscaping(separators, nextIndex + 1);
						continue;
					}
				}
				else if (inQuote)
				{
					nextIndex = s.IndexOfAnyWithEscaping(separators, nextIndex + 1);
					continue;
				}

				if ((nextIndex != 0 || s[nextIndex] != '"') && (lastIndex != nextIndex || !removeEmptyEntries))
				{
					res.Add(s[lastIndex..nextIndex]);
				}

				lastIndex = nextIndex + 1;
				nextIndex = s.IndexOfAnyWithEscaping(separators, lastIndex);
			}

			if ((lastIndex != s.Length || s.Length <= 0 || s[^1] != '"') && (lastIndex != s.Length || !removeEmptyEntries))
			{
				res.Add(s[lastIndex..]);
			}

			return res.ToArray();
		}

		internal static string FromMasterfileLabelRepresentation(this string s)
		{
			_ = s ?? throw new ArgumentNullException(nameof(s));

			var sb = new StringBuilder();

			for (int i = 0; i < s.Length; i++)
			{
				if (s[i] == '\\')
				{
					if (s.Length <= i + 1)
					{
						throw new FormatException("Escape character at end of string");
					}

					i++;
					if (s[i] >= '0' && s[i] <= '9')
					{
						if (s.Length < i + 3)
						{
							throw new FormatException("Partial escape character at end of string");
						}

						sb.Append((char) Byte.Parse(s.Substring(i, 3)));
						i += 2;
					}
					else
					{
						sb.Append(s[i]);
					}
				}
				else
				{
					sb.Append(s[i]);
				}
			}

			return sb.ToString();
		}

		internal static string ToMasterfileLabelRepresentation(this string s, bool encodeDots = false)
		{
			_ = s ?? throw new ArgumentNullException(nameof(s));

			StringBuilder sb = new StringBuilder();

			for (var i = 0; i < s.Length; i++)
			{
				switch (s[i])
				{
					case < ' ':
					case > '\x7e':
						sb.Append(@"\" + ((byte) s[i]).ToString("000"));
						break;
					case '"':
					case '(':
					case ')':
					case ';':
					case '\\':
						sb.Append(@"\" + (char) s[i]);
						break;
					case '.':
						sb.Append(encodeDots ? @"\." : ".");
						break;
					default:
						sb.Append(s[i]);
						break;
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
				bool isLower = _random.Next(0, 100) > 50;

				char current = s[i];

				if (!isLower && current is >= 'A' and <= 'Z')
				{
					current = (char) (current + 0x20);
				}
				else if (isLower && current is >= 'a' and <= 'z')
				{
					current = (char) (current - 0x20);
				}

				res[i] = current;
			}

			return new string(res);
		}
	}
}