using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net
{
	internal static class EnumHelper<T>
		where T : struct
	{
		private static Dictionary<T, string> _names;
		private static Dictionary<string, T> _values;

		static EnumHelper()
		{
			string[] names = Enum.GetNames(typeof(T));
			T[] values = (T[])Enum.GetValues(typeof(T));

			_names = new Dictionary<T, string>(names.Length);
			_values = new Dictionary<string, T>(names.Length * 2);

			for (int i = 0; i < names.Length; i++)
			{
				_names[values[i]] = names[i];
				_values[names[i]] = values[i];
				_values[names[i].ToLower()] = values[i];
			}
		}

		public static bool TryParse(string s, bool ignoreCase, out T value)
		{
			if (String.IsNullOrEmpty(s))
			{
				value = default(T);
				return false;
			}

			return _values.TryGetValue((ignoreCase ? s.ToLower() : s), out value);
		}

		public static string ToString(T value)
		{
			return _names[value];
		}
	}
}
