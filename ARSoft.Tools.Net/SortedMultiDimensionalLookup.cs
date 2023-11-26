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

using System.Collections;
using System.Diagnostics.CodeAnalysis;

namespace ARSoft.Tools.Net;

internal class SortedMultiDimensionalLookup<TKey1, TKey2, TElement> : IEnumerable<KeyValuePair<TKey1, ILookup<TKey2, TElement>>>
	where TKey1 : notnull
	where TKey2 : notnull
{
	private readonly TKey1[] _keys;
	private readonly Dictionary<TKey1, ILookup<TKey2, TElement>> _values;

	public SortedMultiDimensionalLookup(IEnumerable<TElement> values, Func<TElement, TKey1> key1Selector, Func<TElement, TKey2> key2Selector)
	{
		_values = values.GroupBy(key1Selector).ToDictionary(x => x.Key, x => x.ToLookup(key2Selector));
		_keys = _values.Keys.OrderBy(x => x).ToArray();
	}

	public int Count => _keys.Length;

	public ILookup<TKey2, TElement> this[TKey1 key]
	{
		get { return TryGetValue(key, out var values) ? values : Enumerable.Empty<TElement>().ToLookup(x => (TKey2) default!); }
	}

	public KeyValuePair<TKey1, ILookup<TKey2, TElement>> this[int index]
	{
		get
		{
			var key = _keys[index];
			return new KeyValuePair<TKey1, ILookup<TKey2, TElement>>(key, _values[key]);
		}
	}

	public bool ContainsKey(TKey1 key) => _values.ContainsKey(key);

	public bool ContainsKey(TKey1 key1, TKey2 key2) => _values.ContainsKey(key1) && _values[key1].Contains(key2);

	public bool TryGetValue(TKey1 key, [MaybeNullWhen(false)] out ILookup<TKey2, TElement> values) => _values.TryGetValue(key, out values);

	public bool TryGetValue(TKey1 key1, TKey2 key2, [MaybeNullWhen(false)] out IEnumerable<TElement> values)
	{
		if (TryGetValue(key1, out var v))
		{
			if (v.Contains(key2))
			{
				values = v[key2];
				return true;
			}
		}

		values = null;
		return false;
	}

	public IEnumerator<KeyValuePair<TKey1, ILookup<TKey2, TElement>>> GetEnumerator()
	{
		return _keys.Select(k => new KeyValuePair<TKey1, ILookup<TKey2, TElement>>(k, _values[k])).GetEnumerator();
	}

	IEnumerator IEnumerable.GetEnumerator()
	{
		return GetEnumerator();
	}
}