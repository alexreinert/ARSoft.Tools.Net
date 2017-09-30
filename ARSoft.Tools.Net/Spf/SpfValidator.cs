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
	///   Validator for SPF records
	/// </summary>
	public class SpfValidator : ValidatorBase<SpfRecord>
	{
		protected override async Task<LoadRecordResult> LoadRecordsAsync(DomainName domain, CancellationToken token)
		{
			DnsResolveResult<TxtRecord> dnsResult = await ResolveDnsAsync<TxtRecord>(domain, RecordType.Txt, token);
			if ((dnsResult == null) || ((dnsResult.ReturnCode != ReturnCode.NoError) && (dnsResult.ReturnCode != ReturnCode.NxDomain)))
			{
				return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.TempError };
			}

			var spfTextRecords = dnsResult.Records
				.Select(r => r.TextData)
				.Where(SpfRecord.IsSpfRecord)
				.ToList();

			SpfRecord record;

			if (spfTextRecords.Count == 0)
			{
				return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.None };
			}
			else if ((spfTextRecords.Count > 1) || !SpfRecord.TryParse(spfTextRecords[0], out record))
			{
				return new LoadRecordResult() { CouldBeLoaded = false, ErrorResult = SpfQualifier.PermError };
			}
			else
			{
				return new LoadRecordResult() { CouldBeLoaded = true, Record = record };
			}
		}
	}
}