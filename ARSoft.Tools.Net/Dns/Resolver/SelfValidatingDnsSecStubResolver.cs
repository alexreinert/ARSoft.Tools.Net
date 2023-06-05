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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Self validating security aware stub resolver</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc4033.html">RFC 4033</a>
	///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
	///     and <a href="https://www.rfc-editor.org/rfc/rfc4035.html">RFC 4035</a>.
	///   </para>
	/// </summary>
	public class SelfValidatingInternalDnsSecStubResolver : IDnsSecResolver, IInternalDnsSecResolver<ResolveLoopProtector>
	{
		private readonly DnsClient _dnsClient;
		private DnsCache _cache;
		private readonly DnsSecValidator<ResolveLoopProtector> _validator;

		/// <summary>
		///   Provides a new instance using a custom <see cref="DnsClient">DNS client</see>
		/// </summary>
		/// <param name="dnsClient"> The <see cref="DnsClient">DNS client</see> to use </param>
		/// <param name="resolverHintStore"> The resolver hint store with the root DnsKey hints</param>
		public SelfValidatingInternalDnsSecStubResolver(DnsClient? dnsClient = null, IResolverHintStore? resolverHintStore = null)
		{
			_dnsClient = dnsClient ?? DnsClient.Default;
			_cache = new DnsCache();
			_validator = new DnsSecValidator<ResolveLoopProtector>(this, resolverHintStore ?? new StaticResolverHintStore());
		}

		/// <summary>
		///   Provides a new instance using a list of custom DNS servers and a default query timeout of 10 seconds
		/// </summary>
		/// <param name="servers"> The list of servers to use </param>
		public SelfValidatingInternalDnsSecStubResolver(IEnumerable<IPAddress> servers)
			: this(servers, 10000) { }

		/// <summary>
		///   Provides a new instance using a list of custom DNS servers and a custom query timeout
		/// </summary>
		/// <param name="servers"> The list of servers to use </param>
		/// <param name="queryTimeout"> The query timeout in milliseconds </param>
		public SelfValidatingInternalDnsSecStubResolver(IEnumerable<IPAddress> servers, int queryTimeout)
			: this(new DnsClient(servers, queryTimeout)) { }

		/// <summary>
		///   Resolves specified records.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public List<T> Resolve<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
		{
			return ResolveAsync<T>(name, recordType, recordClass).GetAwaiter().GetResult();
		}

		/// <summary>
		///   Resolves specified records as an asynchronous operation.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public async Task<List<T>> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default(CancellationToken))
			where T : DnsRecordBase
		{
			_ = name ?? throw new ArgumentNullException(nameof(name), "Name must be provided");

			var res = await ResolveSecureAsync<T>(name, recordType, recordClass, token);

			return res.Records;
		}

		/// <summary>
		///   Resolves specified records.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public DnsSecResult<T> ResolveSecure<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
		{
			return ResolveSecureAsync<T>(name, recordType, recordClass).GetAwaiter().GetResult();
		}

		/// <summary>
		///   Resolves specified records as an asynchronous operation.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public async Task<DnsSecResult<T>> ResolveSecureAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default(CancellationToken))
			where T : DnsRecordBase
		{
			_ = name ?? throw new ArgumentNullException(nameof(name), "Name must be provided");

			return await ResolveSecureAsyncInternal<T>(name, recordType, recordClass, token, new ResolveLoopProtector());
		}

		private async Task<DnsSecResult<T>> ResolveSecureAsyncInternal<T>(DomainName name, RecordType recordType, RecordClass recordClass, CancellationToken token, ResolveLoopProtector resolveLoopProtector) where T : DnsRecordBase
		{
			using (resolveLoopProtector.AddOrThrow(name, recordType, recordClass))
			{
				if (_cache.TryGetRecords(name, recordType, recordClass, out DnsCacheRecordList<T>? cacheResult))
				{
					return new DnsSecResult<T>(cacheResult!, cacheResult!.ValidationResult);
				}

				DnsMessage? msg = await _dnsClient.ResolveAsync(name, recordType, recordClass, new DnsQueryOptions()
				{
					IsCheckingDisabled = true,
					IsRecursionDesired = true,
					EDnsOptions = DnsQueryOptions.DefaultDnsSecQueryOptions.EDnsOptions
				}, token);

				if ((msg == null) || ((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
				{
					throw new Exception("DNS request failed");
				}

				DnsSecValidationResult validationResult;

				CNameRecord? cName = msg.AnswerRecords.Where(x => (x.RecordType == RecordType.CName) && (x.RecordClass == recordClass) && x.Name.Equals(name)).OfType<CNameRecord>().FirstOrDefault();

				if (cName != null)
				{
					DnsSecValidationResult cNameValidationResult = await _validator.ValidateAsync(name, RecordType.CName, recordClass, msg, new List<CNameRecord>() { cName }, resolveLoopProtector, token);
					if ((cNameValidationResult == DnsSecValidationResult.Bogus) || (cNameValidationResult == DnsSecValidationResult.Indeterminate))
						throw new DnsSecValidationException("CNAME record could not be validated");

					var records = msg.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(cName.CanonicalName)).OfType<T>().ToList();
					if (records.Count > 0)
					{
						DnsSecValidationResult recordsValidationResult = await _validator.ValidateAsync(cName.CanonicalName, recordType, recordClass, msg, records, resolveLoopProtector, token);
						if ((recordsValidationResult == DnsSecValidationResult.Bogus) || (recordsValidationResult == DnsSecValidationResult.Indeterminate))
							throw new DnsSecValidationException("CNAME matching records could not be validated");

						validationResult = cNameValidationResult == recordsValidationResult ? cNameValidationResult : DnsSecValidationResult.Unsigned;
						_cache.Add(name, recordType, recordClass, records, validationResult, Math.Min(cName.TimeToLive, records.Min(x => x.TimeToLive)));

						return new DnsSecResult<T>(records, validationResult);
					}

					var cNameResults = await ResolveSecureAsyncInternal<T>(cName.CanonicalName, recordType, recordClass, token, resolveLoopProtector);
					validationResult = cNameValidationResult == cNameResults.ValidationResult ? cNameValidationResult : DnsSecValidationResult.Unsigned;

					if (cNameResults.Records.Count > 0)
						_cache.Add(name, recordType, recordClass, cNameResults.Records, validationResult, Math.Min(cName.TimeToLive, cNameResults.Records.Min(x => x.TimeToLive)));

					return new DnsSecResult<T>(cNameResults.Records, validationResult);
				}

				List<T> res = msg.AnswerRecords.Where(x => (x.RecordType == recordType) && (x.RecordClass == recordClass) && x.Name.Equals(name)).OfType<T>().ToList();

				validationResult = await _validator.ValidateAsync(name, recordType, recordClass, msg, res, resolveLoopProtector, token);

				if (validationResult == DnsSecValidationResult.Bogus)
					throw new DnsSecValidationException("Response records could not be validated");

				if (res.Count > 0)
					_cache.Add(name, recordType, recordClass, res, validationResult, res.Min(x => x.TimeToLive));

				return new DnsSecResult<T>(res, validationResult);
			}
		}

		/// <summary>
		///   Clears the record cache
		/// </summary>
		public void ClearCache()
		{
			_cache = new DnsCache();
		}

		Task<DnsMessage?> IInternalDnsSecResolver<ResolveLoopProtector>.ResolveMessageAsync(DomainName name, RecordType recordType, RecordClass recordClass, ResolveLoopProtector state, CancellationToken token)
		{
			return _dnsClient.ResolveAsync(name, RecordType.Ds, recordClass, new DnsQueryOptions()
			{
				IsRecursionDesired = true,
				IsCheckingDisabled = true,
				EDnsOptions = DnsQueryOptions.DefaultDnsSecQueryOptions.EDnsOptions
			}, token);
		}

		Task<DnsSecResult<TRecord>> IInternalDnsSecResolver<ResolveLoopProtector>.ResolveSecureAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, ResolveLoopProtector resolveLoopProtector, CancellationToken token)
		{
			return ResolveSecureAsyncInternal<TRecord>(name, recordType, recordClass, token, resolveLoopProtector);
		}

		void IDisposable.Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool isDisposing) { }

		~SelfValidatingInternalDnsSecStubResolver()
		{
			Dispose(false);
		}
	}
}