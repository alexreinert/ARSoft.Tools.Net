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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	internal class DnsCacheRecordList<T> : List<T>
	{
		public DnsSecValidationResult ValidationResult { get; set; }
	}

	internal class DnsCache
	{
		private class CacheKey
		{
			private readonly DomainName _name;
			private readonly RecordClass _recordClass;
			private readonly int _hashCode;
			private readonly RecordType _recordType;

			public CacheKey(DomainName name, RecordType recordType, RecordClass recordClass)
			{
				_name = name;
				_recordClass = recordClass;
				_recordType = recordType;

				_hashCode = name.GetHashCode() ^ (7 * (int) recordType) ^ (11 * (int) recordClass);
			}


			public override int GetHashCode()
			{
				return _hashCode;
			}

			public override bool Equals(object obj)
			{
				CacheKey other = obj as CacheKey;

				if (other == null)
					return false;

				return (_recordType == other._recordType) && (_recordClass == other._recordClass) && (_name.Equals(other._name));
			}

			public override string ToString()
			{
				return _name + " " + _recordClass.ToShortString() + " " + _recordType.ToShortString();
			}
		}

		private class CacheValue
		{
			public DateTime ExpireDateUtc { get; }
			public DnsCacheRecordList<DnsRecordBase> Records { get; }

			public CacheValue(DnsCacheRecordList<DnsRecordBase> records, int timeToLive)
			{
				Records = records;
				ExpireDateUtc = DateTime.UtcNow.AddSeconds(timeToLive);
			}
		}

		private readonly ConcurrentDictionary<CacheKey, CacheValue> _cache = new ConcurrentDictionary<CacheKey, CacheValue>();

		public void Add<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, IEnumerable<TRecord> records, DnsSecValidationResult validationResult, int timeToLive)
			where TRecord : DnsRecordBase
		{
			DnsCacheRecordList<DnsRecordBase> cacheValues = new DnsCacheRecordList<DnsRecordBase>();
			cacheValues.AddRange(records);
			cacheValues.ValidationResult = validationResult;

			Add(name, recordType, recordClass, cacheValues, timeToLive);
		}

		public void Add(DomainName name, RecordType recordType, RecordClass recordClass, DnsCacheRecordList<DnsRecordBase> records, int timeToLive)
		{
			CacheKey key = new CacheKey(name, recordType, recordClass);
			_cache.TryAdd(key, new CacheValue(records, timeToLive));
		}

		public bool TryGetRecords<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, out List<TRecord> records)
			where TRecord : DnsRecordBase
		{
			CacheKey key = new CacheKey(name, recordType, recordClass);
			DateTime utcNow = DateTime.UtcNow;

			CacheValue cacheValue;
			if (_cache.TryGetValue(key, out cacheValue))
			{
				if (cacheValue.ExpireDateUtc < utcNow)
				{
					_cache.TryRemove(key, out cacheValue);
					records = null;
					return false;
				}

				int ttl = (int) (cacheValue.ExpireDateUtc - utcNow).TotalSeconds;

				records = new List<TRecord>();

				records.AddRange(cacheValue
					.Records
					.OfType<TRecord>()
					.Select(x =>
					{
						TRecord record = x.Clone<TRecord>();
						record.TimeToLive = ttl;
						return record;
					}));

				return true;
			}

			records = null;
			return false;
		}

		public bool TryGetRecords<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, out DnsCacheRecordList<TRecord> records)
			where TRecord : DnsRecordBase
		{
			CacheKey key = new CacheKey(name, recordType, recordClass);
			DateTime utcNow = DateTime.UtcNow;

			CacheValue cacheValue;
			if (_cache.TryGetValue(key, out cacheValue))
			{
				if (cacheValue.ExpireDateUtc < utcNow)
				{
					_cache.TryRemove(key, out cacheValue);
					records = null;
					return false;
				}

				int ttl = (int) (cacheValue.ExpireDateUtc - utcNow).TotalSeconds;

				records = new DnsCacheRecordList<TRecord>();

				records.AddRange(cacheValue
					.Records
					.OfType<TRecord>()
					.Select(x =>
					{
						TRecord record = x.Clone<TRecord>();
						record.TimeToLive = ttl;
						return record;
					}));

				records.ValidationResult = cacheValue.Records.ValidationResult;

				return true;
			}

			records = null;
			return false;
		}

		public void RemoveExpiredItems()
		{
			DateTime utcNow = DateTime.UtcNow;

			foreach (var kvp in _cache)
			{
				CacheValue tmp;
				if (kvp.Value.ExpireDateUtc < utcNow)
					_cache.TryRemove(kvp.Key, out tmp);
			}
		}
	}
}