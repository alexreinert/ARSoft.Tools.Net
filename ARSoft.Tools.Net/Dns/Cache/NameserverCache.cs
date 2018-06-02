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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;

namespace ARSoft.Tools.Net.Dns.Cache
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

			public override int GetHashCode() => Address.GetHashCode();

		    public override bool Equals(object obj)
			{
			    if (!(obj is CacheValue second))
					return false;

				return Address.Equals(second.Address);
			}
		}

		private readonly ConcurrentDictionary<DomainName, HashSet<CacheValue>> _cache = new ConcurrentDictionary<DomainName, HashSet<CacheValue>>();

		public void Add(DomainName zoneName, IPAddress address, int timeToLive)
		{

            if (_cache.TryGetValue(zoneName, out var addresses))
                lock (addresses)
                {
                    addresses.Add(new CacheValue(timeToLive, address));
                }
            else
                _cache.TryAdd(zoneName, new HashSet<CacheValue> { new CacheValue(timeToLive, address) });
		}

		public bool TryGetAddresses(DomainName zoneName, out List<IPAddress> addresses)
		{
			var utcNow = DateTime.UtcNow;

            if (_cache.TryGetValue(zoneName, out var cacheValues))
            {
                addresses = new List<IPAddress>();
                var needsCleanup = false;

                lock (cacheValues)
                {
                    foreach (var cacheValue in cacheValues)
                        if (cacheValue.ExpireDateUtc < utcNow)
                            needsCleanup = true;
                        else
                            addresses.Add(cacheValue.Address);

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
			var utcNow = DateTime.UtcNow;

			foreach (var kvp in _cache)
			    lock (kvp.Value)
			    {

			        kvp.Value.RemoveWhere(x => x.ExpireDateUtc < utcNow);
			        if (kvp.Value.Count == 0)
			            _cache.TryRemove(kvp.Key, out var tmp);
			    }
		}
	}
}