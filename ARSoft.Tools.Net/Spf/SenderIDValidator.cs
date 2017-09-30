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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   Validator for SenderID records
	/// </summary>
	public class SenderIDValidator : ValidatorBase<SenderIDRecord>
	{
		/// <summary>
		///   Scope to examin
		/// </summary>
		public SenderIDScope Scope { get; set; }

		/// <summary>
		///   Initializes a new instance of the SenderIDValidator class.
		/// </summary>
		public SenderIDValidator()
		{
			Scope = SenderIDScope.MFrom;
		}

		protected override async Task<LoadRecordResult> LoadRecordsAsync(DomainName domain, CancellationToken token)
		{
			DnsResolveResult<TxtRecord> dnsResult = await ResolveDnsAsync<TxtRecord>(domain, RecordType.Txt, token);
			if ((dnsResult == null) || ((dnsResult.ReturnCode != ReturnCode.NoError) && (dnsResult.ReturnCode != ReturnCode.NxDomain)))
			{
				return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.TempError };
			}
			else if ((Scope == SenderIDScope.Pra) && (dnsResult.ReturnCode == ReturnCode.NxDomain))
			{
				return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.Fail };
			}

			var senderIDTextRecords = dnsResult.Records
				.Select(r => r.TextData)
				.Where(t => SenderIDRecord.IsSenderIDRecord(t, Scope))
				.ToList();

			if (senderIDTextRecords.Count >= 1)
			{
				var potentialRecords = new List<SenderIDRecord>();
				foreach (var senderIDTextRecord in senderIDTextRecords)
				{
					SenderIDRecord tmpRecord;
					if (SenderIDRecord.TryParse(senderIDTextRecord, out tmpRecord))
					{
						potentialRecords.Add(tmpRecord);
					}
					else
					{
						return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.PermError };
					}
				}

				if (potentialRecords.GroupBy(r => r.Version).Any(g => g.Count() > 1))
				{
					return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.PermError };
				}
				else
				{
					return new LoadRecordResult() { CouldBeLoaded = true, ErrorResult = default(SpfQualifier), Record = potentialRecords.OrderByDescending(r => r.Version).First() };
				}
			}
			else
			{
				return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.None };
			}
		}
	}
}