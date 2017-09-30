#region Copyright and License
// Copyright 2010..2015 Alexander Reinert
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
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   Base implementation of a validator for SPF and SenderID records
	/// </summary>
	/// <typeparam name="T"> Type of the record </typeparam>
	public abstract class ValidatorBase<T>
		where T : SpfRecordBase
	{
		/// <summary>
		///   DnsClient which is used for DNS lookups
		///   <para>Default is DnsClient.Default</para>
		/// </summary>
		public DnsClient DnsClient { get; set; }

		/// <summary>
		///   Domain name which was used in HELO/EHLO
		/// </summary>
		public string HeloDomain { get; set; }

		/// <summary>
		///   IP address of the computer validating the record
		///   <para>Default is the first IP the computer</para>
		/// </summary>
		public IPAddress LocalIP { get; set; }

		/// <summary>
		///   Name of the computer validating the record
		///   <para>Default is the computer name</para>
		/// </summary>
		public string LocalDomain { get; set; }

		private int _dnsLookupLimit = 20;

		/// <summary>
		///   The maximum number of DNS lookups allowed
		///   <para>Default is 20</para>
		/// </summary>
		public int DnsLookupLimit
		{
			get { return _dnsLookupLimit; }
			set { _dnsLookupLimit = value; }
		}

		protected abstract Task<LoadRecordResult> LoadRecordsAsync(string domain, Dictionary<string, DnsMessage> dnsCache);

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
		/// <returns> The result of the evaluation </returns>
		public ValidationResult CheckHost(IPAddress ip, string domain, string sender, bool expandExplanation)
		{
			var result = CheckHostInternalAsync(ip, domain, sender, false, new Dictionary<string, DnsMessage>());
			result.Wait();

			return result.Result;
		}

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
		/// <returns> The result of the evaluation </returns>
		public async Task<ValidationResult> CheckHostAsync(IPAddress ip, string domain, string sender, bool expandExplanation)
		{
			return await CheckHostInternalAsync(ip, domain, sender, expandExplanation, new Dictionary<string, DnsMessage>());
		}

		protected class LoadRecordResult
		{
			public bool CouldBeLoaded { get; internal set; }
			public T Record { get; internal set; }
			public SpfQualifier ErrorResult { get; internal set; }
		}

		private async Task<ValidationResult> CheckHostInternalAsync(IPAddress ip, string domain, string sender, bool expandExplanation, Dictionary<string, DnsMessage> dnsCache)
		{
			if (String.IsNullOrEmpty(domain))
			{
				return new ValidationResult() { Result = SpfQualifier.None, Explanation = String.Empty };
			}

			if (domain.Contains('@'))
				throw new ArgumentException("Domain should not be an email address", "domain");

			if (String.IsNullOrEmpty(sender))
			{
				sender = "postmaster@unknown";
			}
			else if (!sender.Contains('@'))
			{
				sender = "postmaster@" + sender;
			}

			LoadRecordResult loadResult = await LoadRecordsAsync(domain, dnsCache);

			if (!loadResult.CouldBeLoaded)
			{
				return new ValidationResult() { Result = loadResult.ErrorResult, Explanation = String.Empty };
			}

			T record = loadResult.Record;

			if ((record.Terms == null) || (record.Terms.Count == 0))
				return new ValidationResult() { Result = SpfQualifier.Neutral, Explanation = String.Empty };


			if (record.Terms.OfType<SpfModifier>().GroupBy(m => m.Type).Where(g => (g.Key == SpfModifierType.Exp) || (g.Key == SpfModifierType.Redirect)).Any(g => g.Count() > 1))
				return new ValidationResult() { Result = SpfQualifier.PermError, Explanation = String.Empty };

			ValidationResult result = new ValidationResult() { Result = loadResult.ErrorResult };

			#region Evaluate mechanism
			foreach (SpfMechanism mechanism in record.Terms.OfType<SpfMechanism>())
			{
				if (dnsCache.Count > DnsLookupLimit)
					return new ValidationResult() { Result = SpfQualifier.PermError, Explanation = String.Empty };

				SpfQualifier qualifier = await CheckMechanismAsync(mechanism, ip, domain, sender, dnsCache);

				if (qualifier != SpfQualifier.None)
				{
					result.Result = qualifier;
					break;
				}
			}
			#endregion

			#region Evaluate modifiers
			if (result.Result == SpfQualifier.None)
			{
				SpfModifier redirectModifier = record.Terms.OfType<SpfModifier>().FirstOrDefault(m => m.Type == SpfModifierType.Redirect);
				if (redirectModifier != null)
				{
					string redirectDomain = await ExpandDomainAsync(redirectModifier.Domain ?? String.Empty, ip, domain, sender, dnsCache);

					if (String.IsNullOrEmpty(redirectDomain) || (redirectDomain.Equals(domain, StringComparison.InvariantCultureIgnoreCase)))
					{
						result.Result = SpfQualifier.PermError;
					}
					else
					{
						result = await CheckHostInternalAsync(ip, redirectDomain, sender, expandExplanation, dnsCache);

						if (result.Result == SpfQualifier.None)
							result.Result = SpfQualifier.PermError;
					}
				}
			}
			else if ((result.Result == SpfQualifier.Fail) && expandExplanation)
			{
				SpfModifier expModifier = record.Terms.OfType<SpfModifier>().Where(m => m.Type == SpfModifierType.Exp).FirstOrDefault();
				if (expModifier != null)
				{
					string target = await ExpandDomainAsync(expModifier.Domain, ip, domain, sender, dnsCache);

					if (String.IsNullOrEmpty(target))
					{
						result.Explanation = String.Empty;
					}
					else
					{
						DnsResolveResult<TxtRecord> dnsResult = await ResolveDnsAsync<TxtRecord>(target, RecordType.Txt, dnsCache);
						if ((dnsResult != null) && (dnsResult.ReturnCode == ReturnCode.NoError))
						{
							TxtRecord txtRecord = dnsResult.Records.FirstOrDefault();
							if (txtRecord != null)
							{
								result.Explanation = await ExpandDomainAsync(txtRecord.TextData, ip, domain, sender, dnsCache);
							}
						}
					}
				}
			}
			#endregion

			if (result.Result == SpfQualifier.None)
				result.Result = SpfQualifier.Neutral;

			return result;
		}

		private async Task<SpfQualifier> CheckMechanismAsync(SpfMechanism mechanism, IPAddress ip, string domain, string sender, Dictionary<string, DnsMessage> dnsCache)
		{
			switch (mechanism.Type)
			{
				case SpfMechanismType.All:
					return mechanism.Qualifier;

				case SpfMechanismType.A:
					bool? isAMatch = await IsIpMatchAsync(String.IsNullOrEmpty(mechanism.Domain) ? domain : mechanism.Domain, ip, mechanism.Prefix, mechanism.Prefix6, dnsCache);
					if (!isAMatch.HasValue)
						return SpfQualifier.TempError;

					if (isAMatch.Value)
					{
						return mechanism.Qualifier;
					}
					break;

				case SpfMechanismType.Mx:
					DnsResolveResult<MxRecord> dnsMxResult = await ResolveDnsAsync<MxRecord>(await ExpandDomainAsync(String.IsNullOrEmpty(mechanism.Domain) ? domain : mechanism.Domain, ip, domain, sender, dnsCache), RecordType.Mx, dnsCache);
					if ((dnsMxResult == null) || ((dnsMxResult.ReturnCode != ReturnCode.NoError) && (dnsMxResult.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					int mxCheckedCount = 0;

					foreach (MxRecord mxRecord in dnsMxResult.Records)
					{
						if (++mxCheckedCount == 10)
							break;

						bool? isMxMatch = await IsIpMatchAsync(mxRecord.ExchangeDomainName, ip, mechanism.Prefix, mechanism.Prefix6, dnsCache);
						if (!isMxMatch.HasValue)
							return SpfQualifier.TempError;

						if (isMxMatch.Value)
						{
							return mechanism.Qualifier;
						}
					}
					break;

				case SpfMechanismType.Ip4:
				case SpfMechanismType.Ip6:
					IPAddress compareAddress;
					if (IPAddress.TryParse(mechanism.Domain, out compareAddress))
					{
						if (ip.AddressFamily != compareAddress.AddressFamily)
							return SpfQualifier.None;

						if (mechanism.Prefix.HasValue)
						{
							if ((mechanism.Prefix.Value < 0) || (mechanism.Prefix.Value > (compareAddress.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32)))
								return SpfQualifier.PermError;

							if (ip.GetNetworkAddress(mechanism.Prefix.Value).Equals(compareAddress.GetNetworkAddress(mechanism.Prefix.Value)))
							{
								return mechanism.Qualifier;
							}
						}
						else if (ip.Equals(compareAddress))
						{
							return mechanism.Qualifier;
						}
					}
					else
					{
						return SpfQualifier.PermError;
					}

					break;

				case SpfMechanismType.Ptr:
					DnsResolveResult<PtrRecord> dnsPtrResult = await ResolveDnsAsync<PtrRecord>(ip.GetReverseLookupAddress(), RecordType.Ptr, dnsCache);
					if ((dnsPtrResult == null) || ((dnsPtrResult.ReturnCode != ReturnCode.NoError) && (dnsPtrResult.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					string ptrCompareName = String.IsNullOrEmpty(mechanism.Domain) ? domain : mechanism.Domain;

					int ptrCheckedCount = 0;
					foreach (PtrRecord ptrRecord in dnsPtrResult.Records)
					{
						if (++ptrCheckedCount == 10)
							break;

						bool? isPtrMatch = await IsIpMatchAsync(ptrRecord.PointerDomainName, ip, 0, 0, dnsCache);
						if (isPtrMatch.HasValue && isPtrMatch.Value)
						{
							if (ptrRecord.PointerDomainName.Equals(ptrCompareName, StringComparison.InvariantCultureIgnoreCase) || (ptrRecord.PointerDomainName.EndsWith("." + ptrCompareName, StringComparison.InvariantCultureIgnoreCase)))
								return mechanism.Qualifier;
						}
					}
					break;

				case SpfMechanismType.Exist:
					if (String.IsNullOrEmpty(mechanism.Domain))
						return SpfQualifier.PermError;

					DnsResolveResult<ARecord> dnsAResult = await ResolveDnsAsync<ARecord>(await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, dnsCache), RecordType.A, dnsCache);
					if ((dnsAResult == null) || ((dnsAResult.ReturnCode != ReturnCode.NoError) && (dnsAResult.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					if (dnsAResult.Records.Count(record => (record.RecordType == RecordType.A)) > 0)
					{
						return mechanism.Qualifier;
					}
					break;

				case SpfMechanismType.Include:
					if (String.IsNullOrEmpty(mechanism.Domain) || (mechanism.Domain.Equals(domain, StringComparison.InvariantCultureIgnoreCase)))
						return SpfQualifier.PermError;

					string includeDomain = await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, dnsCache);
					var includeResult = await CheckHostInternalAsync(ip, sender, includeDomain, false, dnsCache);
					switch (includeResult.Result)
					{
						case SpfQualifier.Pass:
							return mechanism.Qualifier;

						case SpfQualifier.Fail:
						case SpfQualifier.SoftFail:
						case SpfQualifier.Neutral:
							return SpfQualifier.None;

						case SpfQualifier.TempError:
							return SpfQualifier.TempError;

						case SpfQualifier.PermError:
						case SpfQualifier.None:
							return SpfQualifier.PermError;
					}
					break;

				default:
					return SpfQualifier.PermError;
			}

			return SpfQualifier.None;
		}

		private async Task<bool?> IsIpMatchAsync(string domain, IPAddress ipAddress, int? prefix4, int? prefix6, Dictionary<string, DnsMessage> dnsCache)
		{
			if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
			{
				if (prefix6.HasValue)
					ipAddress = ipAddress.GetNetworkAddress(prefix6.Value);

				return await IsIpMatchAsync<AaaaRecord>(domain, ipAddress, prefix6, RecordType.Aaaa, dnsCache);
			}
			else
			{
				if (prefix4.HasValue)
					ipAddress = ipAddress.GetNetworkAddress(prefix4.Value);

				return await IsIpMatchAsync<ARecord>(domain, ipAddress, prefix4, RecordType.A, dnsCache);
			}
		}

		private async Task<bool?> IsIpMatchAsync<TRecord>(string domain, IPAddress ipAddress, int? prefix, RecordType recordType, Dictionary<string, DnsMessage> dnsCache)
			where TRecord : DnsRecordBase, IAddressRecord
		{
			DnsResolveResult<TRecord> dnsResult = await ResolveDnsAsync<TRecord>(domain, recordType, dnsCache);
			if ((dnsResult == null) || ((dnsResult.ReturnCode != ReturnCode.NoError) && (dnsResult.ReturnCode != ReturnCode.NxDomain)))
				return null;

			foreach (var dnsRecord in dnsResult.Records)
			{
				if (prefix.HasValue)
				{
					if (ipAddress.Equals(dnsRecord.Address.GetNetworkAddress(prefix.Value)))
						return true;
				}
				else
				{
					if (ipAddress.Equals(dnsRecord.Address))
						return true;
				}
			}

			return false;
		}

		protected class DnsResolveResult<TRecord>
			where TRecord : DnsRecordBase
		{
			public ReturnCode ReturnCode { get; private set; }
			public List<TRecord> Records { get; private set; }

			public DnsResolveResult(ReturnCode returnCode, List<TRecord> records)
			{
				ReturnCode = returnCode;
				Records = records;
			}
		}

		protected async Task<DnsResolveResult<TRecord>> ResolveDnsAsync<TRecord>(string domain, RecordType recordType, Dictionary<string, DnsMessage> dnsCache)
			where TRecord : DnsRecordBase
		{
			DnsMessage msg = await ResolveDnsMessageAsync(domain, recordType, dnsCache);

			if ((msg == null) || ((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
			{
				return new DnsResolveResult<TRecord>(msg.ReturnCode, new List<TRecord>());
			}

			CNameRecord cName = msg.AnswerRecords.Where(x => x.Name.Equals(domain, StringComparison.OrdinalIgnoreCase)).OfType<CNameRecord>().FirstOrDefault();

			if (cName != null)
			{
				var records = msg.AnswerRecords.Where(x => x.Name.Equals(cName.CanonicalName, StringComparison.OrdinalIgnoreCase)).OfType<TRecord>().ToList();
				if (records.Count > 0)
					return new DnsResolveResult<TRecord>(msg.ReturnCode, records);

				return await ResolveDnsAsync<TRecord>(cName.CanonicalName, recordType, dnsCache);
			}

			return new DnsResolveResult<TRecord>(msg.ReturnCode, msg.AnswerRecords.Where(x => x.Name.Equals(domain, StringComparison.OrdinalIgnoreCase)).OfType<TRecord>().ToList());
		}

		protected async Task<DnsMessage> ResolveDnsMessageAsync(string domain, RecordType recordType, Dictionary<string, DnsMessage> dnsCache)
		{
			string key = EnumHelper<RecordType>.ToString(recordType) + "|" + domain;

			DnsMessage msg;
			if (!dnsCache.TryGetValue(key, out msg))
			{
				msg = await (DnsClient ?? DnsClient.Default).ResolveAsync(domain, recordType);
				dnsCache[key] = msg;
			}

			return msg;
		}

		private async Task<string> ExpandDomainAsync(string pattern, IPAddress ip, string domain, string sender, Dictionary<string, DnsMessage> dnsCache)
		{
			if (String.IsNullOrEmpty(pattern))
				return String.Empty;

			Regex regex = new Regex(@"(%%|%_|%-|%\{(?<letter>[slodiphcrtv])(?<count>\d*)(?<reverse>r?)(?<delimiter>[\.\-+,/=]*)})", RegexOptions.Compiled);

			Match match = regex.Match(pattern);
			if (!match.Success)
			{
				return pattern;
			}

			StringBuilder sb = new StringBuilder();
			int pos = 0;
			do
			{
				if (match.Index != pos)
				{
					sb.Append(pattern, pos, match.Index - pos);
				}
				pos = match.Index + match.Length;
				sb.Append(await ExpandMacroAsync(match, ip, domain, sender, dnsCache));
				match = match.NextMatch();
			} while (match.Success);

			if (pos < pattern.Length)
			{
				sb.Append(pattern, pos, pattern.Length - pos);
			}

			return sb.ToString();
		}

		private async Task<string> ExpandMacroAsync(Match pattern, IPAddress ip, string domain, string sender, Dictionary<string, DnsMessage> dnsCache)
		{
			switch (pattern.Value)
			{
				case "%%":
					return "%";
				case "%_":
					return "_";
				case "%-":
					return "-";

				default:
					string letter;
					switch (pattern.Groups["letter"].Value)
					{
						case "s":
							letter = sender;
							break;
						case "l":
							// no boundary check needed, sender is validated on start of CheckHost
							letter = sender.Split('@')[0];
							break;
						case "o":
							// no boundary check needed, sender is validated on start of CheckHost
							letter = sender.Split('@')[1];
							break;
						case "d":
							letter = domain;
							break;
						case "i":
							letter = String.Join(".", ip.GetAddressBytes().Select(b => b.ToString()).ToArray());
							break;
						case "p":
							letter = "unknown";

							DnsResolveResult<PtrRecord> dnsResult = await ResolveDnsAsync<PtrRecord>(ip.GetReverseLookupAddress(), RecordType.Ptr, dnsCache);
							if ((dnsResult == null) || ((dnsResult.ReturnCode != ReturnCode.NoError) && (dnsResult.ReturnCode != ReturnCode.NxDomain)))
							{
								break;
							}

							int ptrCheckedCount = 0;
							foreach (PtrRecord ptrRecord in dnsResult.Records)
							{
								if (++ptrCheckedCount == 10)
									break;

								bool? isPtrMatch = await IsIpMatchAsync(ptrRecord.PointerDomainName, ip, 0, 0, dnsCache);
								if (isPtrMatch.HasValue && isPtrMatch.Value)
								{
									if (letter == "unknown" || ptrRecord.PointerDomainName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
									{
										// use value, if first record or subdomain
										// but evaluate the other records
										letter = ptrRecord.PointerDomainName;
									}
									else if (ptrRecord.PointerDomainName.Equals(domain, StringComparison.OrdinalIgnoreCase))
									{
										// ptr equal domain --> best match, use it
										letter = ptrRecord.PointerDomainName;
										break;
									}
								}
							}
							break;
						case "v":
							letter = (ip.AddressFamily == AddressFamily.InterNetworkV6) ? "ip6" : "in-addr";
							break;
						case "h":
							letter = String.IsNullOrEmpty(HeloDomain) ? "unknown" : HeloDomain;
							break;
						case "c":
							IPAddress address =
								LocalIP
								?? NetworkInterface.GetAllNetworkInterfaces()
								                   .Where(n => (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
								                   .SelectMany(n => n.GetIPProperties().UnicastAddresses)
								                   .Select(u => u.Address)
								                   .FirstOrDefault(a => a.AddressFamily == ip.AddressFamily)
								?? ((ip.AddressFamily == AddressFamily.InterNetwork) ? IPAddress.Loopback : IPAddress.IPv6Loopback);
							letter = address.ToString();
							break;
						case "r":
							letter = String.IsNullOrEmpty(LocalDomain) ? System.Net.Dns.GetHostName() : LocalDomain;
							break;
						case "t":
							letter = ((int) (new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) - DateTime.Now).TotalSeconds).ToString();
							break;
						default:
							return null;
					}

					// only letter
					if (pattern.Value.Length == 4)
						return letter;

					char[] delimiters = pattern.Groups["delimiter"].Value.ToCharArray();
					if (delimiters.Length == 0)
						delimiters = new[] { '.' };

					string[] parts = letter.Split(delimiters);

					if (pattern.Groups["reverse"].Value == "r")
						parts = parts.Reverse().ToArray();

					int count = Int32.MaxValue;
					if (!String.IsNullOrEmpty(pattern.Groups["count"].Value))
					{
						count = Int32.Parse(pattern.Groups["count"].Value);
					}

					if (count < 1)
						return null;

					count = Math.Min(count, parts.Length);

					return String.Join(".", parts, (parts.Length - count), count);
			}
		}
	}
}