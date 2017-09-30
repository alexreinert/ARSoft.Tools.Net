#region Copyright and License
// Copyright 2010..11 Alexander Reinert
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
using ARSoft.Tools.Net.Dns;

namespace ARSoft.Tools.Net.Spf
{
	public class SpfRecord
	{
		public List<SpfTerm> Terms { get; set; }

		public override string ToString()
		{
			StringBuilder res = new StringBuilder();
			res.Append("v=spf1");

			if ((Terms != null) && (Terms.Count > 0))
			{
				foreach (SpfTerm term in Terms)
				{
					SpfModifier modifier = term as SpfModifier;
					if ((modifier == null) || (modifier.Type != SpfModifierType.Unknown))
					{
						res.Append(" ");
						res.Append(term.ToString());
					}
				}
			}

			return res.ToString();
		}

		public static bool TryParse(string s, out SpfRecord value)
		{
			if (String.IsNullOrEmpty(s) || !s.StartsWith("v=spf1 "))
			{
				value = null;
				return false;
			}

			string[] terms = s.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

			value = new SpfRecord { Terms = new List<SpfTerm>() };

			for (int i = 1; i < terms.Length; i++)
			{
				SpfTerm term;
				if (SpfTerm.TryParse(terms[i], out term))
				{
					value.Terms.Add(term);
				}
				else
				{
					value = null;
					return false;
				}
			}

			return true;
		}

		public static SpfQualifier CheckHost(IPAddress clientAddress, string clientName, string heloName, string domain, string sender)
		{
			return String.IsNullOrEmpty(domain) ? SpfQualifier.None : CheckHost(domain, new SpfCheckHostParameter(clientAddress, clientName, heloName, domain, sender));
		}

		internal static SpfQualifier CheckHost(string spfDomain, SpfCheckHostParameter parameters)
		{
			#region First try "real" spf records
			List<SpfRecord> spfRecords = GetValidSpfRecords<Dns.SpfRecord>(spfDomain, RecordType.Spf);
			if (spfRecords == null)
			{
				return SpfQualifier.TempError;
			}
			else if (spfRecords.Count > 1)
			{
				return SpfQualifier.PermError;
			}
			else if (spfRecords.Count == 1)
			{
				return spfRecords[0].CheckHost(parameters);
			}
			#endregion

			#region Then fallback to TXT records
			spfRecords = GetValidSpfRecords<TxtRecord>(spfDomain, RecordType.Txt);
			if (spfRecords == null)
			{
				return SpfQualifier.TempError;
			}
			else if (spfRecords.Count > 1)
			{
				return SpfQualifier.PermError;
			}
			else if (spfRecords.Count == 1)
			{
				return spfRecords[0].CheckHost(parameters);
			}
			else
			{
				return SpfQualifier.None;
			}
			#endregion
		}

		private static List<SpfRecord> GetValidSpfRecords<T>(string spfDomain, RecordType recordType)
			where T: ITextRecord
		{
			List<SpfRecord> res = new List<SpfRecord>();

			DnsMessage dnsMessage = DnsClient.Default.Resolve(spfDomain, recordType);
			if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
			{
				return null;
			}

			foreach (T txtRecord in dnsMessage.AnswerRecords.Where(record => record.RecordType == recordType).Cast<T>())
			{
				SpfRecord spfRecord;
				if (TryParse(txtRecord.TextData, out spfRecord))
					res.Add(spfRecord);
			}

			return res;
		}

		internal SpfQualifier CheckHost(SpfCheckHostParameter parameters)
		{
			if (String.IsNullOrEmpty(parameters.Sender))
				return SpfQualifier.PermError;

			if (!parameters.Sender.Contains('@'))
				parameters.Sender = "postmaster@" + parameters.Sender;

			if (parameters.LoopCount > 15)
				return SpfQualifier.PermError;

			if ((Terms == null) || (Terms.Count == 0))
				return SpfQualifier.Neutral;

			foreach (SpfTerm term in Terms)
			{
				SpfQualifier qualifier = term.CheckHost(parameters);

				if (qualifier != SpfQualifier.None)
					return qualifier;
			}

			return SpfQualifier.Neutral;
		}
	}
}