#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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

using System.Collections.ObjectModel;
using ARSoft.Tools.Net.Dns;

namespace ARSoft.Tools.Net;

internal static class EnumerableExtensions
{
	public static IEnumerable<T> WhereNotNull<T>(this IEnumerable<T?> data)
	{
		foreach (var item in data)
		{
			if (item != null)
				yield return item;
		}
	}

	public static T? SingleOrDefaultIfMultiple<T>(this IEnumerable<T> items)
	{
		using var enumerator = items.GetEnumerator();

		if (!enumerator.MoveNext())
			return default;

		var res = enumerator.Current;

		return enumerator.MoveNext() ? default : res;
	}

	public static T? SingleOrDefaultIfMultiple<T>(this IEnumerable<T> items, Func<T, bool> predicate)
	{
		return items.Where(predicate).SingleOrDefault();
	}
}