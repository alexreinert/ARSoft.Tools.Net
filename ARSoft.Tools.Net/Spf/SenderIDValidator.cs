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

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;
using ARSoft.Tools.Net.Dns.DnsRecord;

namespace ARSoft.Tools.Net.Spf
{
    /// <summary>
    ///   Validator for SenderID records
    /// </summary>
    public class SenderIdValidator : ValidatorBase<SenderIdRecord>
	{
		/// <summary>
		///   Scope to examin
		/// </summary>
		public SenderIdScope Scope { get; set; }

		/// <summary>
		///   Initializes a new instance of the SenderIDValidator class.
		/// </summary>
		public SenderIdValidator() => Scope = SenderIdScope.MFrom;

	    protected override async Task<LoadRecordResult> LoadRecordsAsync(DomainName domain, CancellationToken token)
		{
			var dnsResult = await ResolveDnsAsync<TxtRecord>(domain, RecordType.Txt, token);
			if (dnsResult == null || dnsResult.ReturnCode != ReturnCode.NoError && dnsResult.ReturnCode != ReturnCode.NxDomain)
			    return new LoadRecordResult { CouldBeLoaded = false, ErrorResult = SpfQualifier.TempError };
			else if (Scope == SenderIdScope.Pra && dnsResult.ReturnCode == ReturnCode.NxDomain) return new LoadRecordResult { CouldBeLoaded = false, ErrorResult = SpfQualifier.Fail };

		    var senderIdTextRecords = dnsResult.Records
				.Select(r => r.TextData)
				.Where(t => SenderIdRecord.IsSenderIdRecord(t, Scope))
				.ToList();

			if (senderIdTextRecords.Count >= 1)
			{
				var potentialRecords = new List<SenderIdRecord>();
				foreach (var senderIdTextRecord in senderIdTextRecords)
				    if (SenderIdRecord.TryParse(senderIdTextRecord, out var tmpRecord))
				        potentialRecords.Add(tmpRecord);
				    else
				        return new LoadRecordResult { CouldBeLoaded = false, ErrorResult = SpfQualifier.PermError };

			    if (potentialRecords.GroupBy(r => r.Version).Any(g => g.Count() > 1))
			        return new LoadRecordResult { CouldBeLoaded = false, ErrorResult = SpfQualifier.PermError };
			    else
			        return new LoadRecordResult { CouldBeLoaded = true, ErrorResult = default(SpfQualifier), Record = potentialRecords.OrderByDescending(r => r.Version).First() };
			}
			else
			{
				return new LoadRecordResult { CouldBeLoaded = false, ErrorResult = SpfQualifier.None };
			}
		}
	}
}