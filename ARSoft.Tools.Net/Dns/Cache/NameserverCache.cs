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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	internal class NameserverCache
	{
		private class CacheValue
		{
			public DateTime ExpireDateUtc { get; }
			public IPAddress Address { get; }

			public CacheValue(int timeToLive, IPAddress address)
			{
				ExpireDateUtc = DateTime.UtcNow.AddSeconds(timeToLive);
				Address = address;
			}

			public override int GetHashCode()
			{
				return Address.GetHashCode();
			}

			public override bool Equals(object obj)
			{
				CacheValue second = obj as CacheValue;

				if (second == null)
					return false;

				return Address.Equals(second.Address);
			}
		}

		private readonly ConcurrentDictionary<DomainName, HashSet<CacheValue>> _cache = new ConcurrentDictionary<DomainName, HashSet<CacheValue>>();

		public void Add(DomainName zoneName, IPAddress address, int timeToLive)
		{
			HashSet<CacheValue> addresses;

			if (_cache.TryGetValue(zoneName, out addresses))
			{
				lock (addresses)
				{
					addresses.Add(new CacheValue(timeToLive, address));
				}
			}
			else
			{
				_cache.TryAdd(zoneName, new HashSet<CacheValue>() { new CacheValue(timeToLive, address) });
			}
		}

		public bool TryGetAddresses(DomainName zoneName, out List<IPAddress> addresses)
		{
			DateTime utcNow = DateTime.UtcNow;

			HashSet<CacheValue> cacheValues;
			if (_cache.TryGetValue(zoneName, out cacheValues))
			{
				addresses = new List<IPAddress>();
				bool needsCleanup = false;

				lock (cacheValues)
				{
					foreach (CacheValue cacheValue in cacheValues)
					{
						if (cacheValue.ExpireDateUtc < utcNow)
						{
							needsCleanup = true;
						}
						else
						{
							addresses.Add(cacheValue.Address);
						}
					}

					if (needsCleanup)
					{
						cacheValues.RemoveWhere(x => x.ExpireDateUtc < utcNow);
						if (cacheValues.Count == 0)
#pragma warning disable 0728
							_cache.TryRemove(zoneName, out cacheValues);
#pragma warning restore 0728
					}
				}

				if (addresses.Count > 0)
					return true;
			}

			addresses = null;
			return false;
		}

		public void RemoveExpiredItems()
		{
			DateTime utcNow = DateTime.UtcNow;

			foreach (var kvp in _cache)
			{
				lock (kvp.Value)
				{
					HashSet<CacheValue> tmp;

					kvp.Value.RemoveWhere(x => x.ExpireDateUtc < utcNow);
					if (kvp.Value.Count == 0)
						_cache.TryRemove(kvp.Key, out tmp);
				}
			}
		}
	}
}