﻿#region Copyright and License

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

using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Spf
{
    /// <summary>
    ///     Represents a single term of a SPF record
    /// </summary>
    public class SpfTerm
    {
        private static readonly Regex _parseMechanismRegex =
            new Regex(
                @"^(\s)*(?<qualifier>[~+?-]?)(?<type>[a-z0-9]+)(:(?<domain>[^/]+))?(/(?<prefix>[0-9]+)(/(?<prefix6>[0-9]+))?)?(\s)*$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex _parseModifierRegex = new Regex(@"^(\s)*(?<type>[a-z]+)=(?<domain>[^\s]+)(\s)*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        internal static bool TryParse(string s, out SpfTerm value)
        {
            if (string.IsNullOrEmpty(s))
            {
                value = null;
                return false;
            }

            #region Parse Mechanism

            var match = _parseMechanismRegex.Match(s);
            if (match.Success)
            {
                var mechanism = new SpfMechanism();

                switch (match.Groups["qualifier"].Value)
                {
                    case "+":
                        mechanism.Qualifier = SpfQualifier.Pass;
                        break;
                    case "-":
                        mechanism.Qualifier = SpfQualifier.Fail;
                        break;
                    case "~":
                        mechanism.Qualifier = SpfQualifier.SoftFail;
                        break;
                    case "?":
                        mechanism.Qualifier = SpfQualifier.Neutral;
                        break;

                    default:
                        mechanism.Qualifier = SpfQualifier.Pass;
                        break;
                }

                mechanism.Type = EnumHelper<SpfMechanismType>.TryParse(match.Groups["type"].Value, true, out var type)
                    ? type
                    : SpfMechanismType.Unknown;

                mechanism.Domain = match.Groups["domain"].Value;

                var tmpPrefix = match.Groups["prefix"].Value;
                if (!string.IsNullOrEmpty(tmpPrefix) && int.TryParse(tmpPrefix, out var prefix))
                    mechanism.Prefix = prefix;

                tmpPrefix = match.Groups["prefix6"].Value;
                if (!string.IsNullOrEmpty(tmpPrefix) && int.TryParse(tmpPrefix, out prefix)) mechanism.Prefix6 = prefix;

                value = mechanism;
                return true;
            }

            #endregion

            #region Parse Modifier

            match = _parseModifierRegex.Match(s);
            if (match.Success)
            {
                var modifier = new SpfModifier
                {
                    Type = EnumHelper<SpfModifierType>.TryParse(match.Groups["type"].Value, true, out var type)
                        ? type
                        : SpfModifierType.Unknown,
                    Domain = match.Groups["domain"].Value
                };

                value = modifier;
                return true;
            }

            #endregion

            value = null;
            return false;
        }
    }
}