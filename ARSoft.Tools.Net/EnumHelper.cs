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

using System;
using System.Collections.Generic;

namespace ARSoft.Tools.Net
{
    internal static class EnumHelper<T>
        where T : struct
    {
        private static readonly Dictionary<string, T> _values;

        static EnumHelper()
        {
            var names = Enum.GetNames(typeof(T));
            var values = (T[]) Enum.GetValues(typeof(T));

            Names = new Dictionary<T, string>(names.Length);
            _values = new Dictionary<string, T>(names.Length * 2);

            for (var i = 0; i < names.Length; i++)
            {
                Names[values[i]] = names[i];
                _values[names[i]] = values[i];
                _values[names[i].ToLower()] = values[i];
            }
        }

        public static Dictionary<T, string> Names { get; }

        public static bool TryParse(string s, bool ignoreCase, out T value)
        {
            if (string.IsNullOrEmpty(s))
            {
                value = default(T);
                return false;
            }

            return _values.TryGetValue(ignoreCase ? s.ToLower() : s, out value);
        }

        public static string ToString(T value) =>
            Names.TryGetValue(value, out var res) ? res : Convert.ToInt64(value).ToString();

        internal static T Parse(string s, bool ignoreCase, T defaultValue) =>
            TryParse(s, ignoreCase, out var res) ? res : defaultValue;

        internal static T Parse(string s, bool ignoreCase)
        {
            if (TryParse(s, ignoreCase, out var res))
                return res;

            throw new ArgumentOutOfRangeException(nameof(s));
        }
    }
}