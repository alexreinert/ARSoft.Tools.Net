using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ARSoft.Tools.Net.Dns;
using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Spf
{
	public class SpfTerm
	{
		internal static bool TryParse(string s, out SpfTerm value)
		{
			if (String.IsNullOrEmpty(s))
			{
				value = null;
				return false;
			}

			#region Parse Mechanism
			Regex regex = new Regex(@"^(\s)*(?<qualifier>[~+?-]?)(?<type>[a-z]+)(:(?<domain>[^/]+))?(/(?<prefix>[0-9]+))?(//(?<prefix6>[0-9]+))?(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
			Match match = regex.Match(s);
			if (match.Success)
			{
				SpfMechanism mechanism = new SpfMechanism();

				switch (match.Groups["qualifier"].Value)
				{
					case "+":
						mechanism.Qualifier = SpfQualifier.Pass;
						break;
					case "-":
						mechanism.Qualifier = SpfQualifier.Fail;
						break;
					case "~":
						mechanism.Qualifier = SpfQualifier.SoftFail;
						break;
					case "?":
						mechanism.Qualifier = SpfQualifier.Neutral;
						break;

					default:
						mechanism.Qualifier = SpfQualifier.Pass;
						break;
				}

				SpfMechanismType type;
				if (EnumHelper<SpfMechanismType>.TryParse(match.Groups["type"].Value, true, out type))
				{
					mechanism.Type = type;
				}
				else
				{
					mechanism.Type = SpfMechanismType.Unknown;
				}

				mechanism.Domain = match.Groups["domain"].Value;

				string tmpPrefix = match.Groups["prefix"].Value;
				int prefix;
				if (!String.IsNullOrEmpty(tmpPrefix) && Int32.TryParse(tmpPrefix, out prefix))
				{
					mechanism.Prefix = prefix;
				}

				tmpPrefix = match.Groups["prefix6"].Value;
				if (!String.IsNullOrEmpty(tmpPrefix) && Int32.TryParse(tmpPrefix, out prefix))
				{
					mechanism.Prefix6 = prefix;
				}

				value = mechanism;
				return true;
			}
			#endregion
			#region Parse Modifier
			regex = new Regex(@"^(\s)*(?<type>[a-z]+)=(?<domain>[^\s]+)(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
			match = regex.Match(s);
			if (match.Success)
			{
				SpfModifier modifier = new SpfModifier();

				SpfModifierType type;
				if (EnumHelper<SpfModifierType>.TryParse(match.Groups["type"].Value, true, out type))
				{
					modifier.Type = type;
				}
				else
				{
					modifier.Type = SpfModifierType.Unknown;
				}
				modifier.Domain = match.Groups["domain"].Value;

				value = modifier;
				return true;
			}
			#endregion

			value = null;
			return false;
		}

		#region CheckHost
		internal SpfQualifier CheckHost(SpfCheckHostParameter parameters)
		{
			DnsMessage dnsMessage;

			SpfMechanism spfMechanism = this as SpfMechanism;
			if (spfMechanism != null)
			{
				switch (spfMechanism.Type)
				{
					case SpfMechanismType.All:
						return spfMechanism.Qualifier;

					case SpfMechanismType.A:
						bool? isAMatch = IsIpMatch(String.IsNullOrEmpty(spfMechanism.Domain) ? parameters.CurrentDomain : spfMechanism.Domain, parameters.ClientAddress, spfMechanism.Prefix, spfMechanism.Prefix6);
						if (!isAMatch.HasValue)
							return SpfQualifier.TempError;

						if (isAMatch.Value)
						{
							return spfMechanism.Qualifier;
						}
						break;

					case SpfMechanismType.Mx:
						dnsMessage = DnsClient.Default.Resolve(ExpandDomain(String.IsNullOrEmpty(spfMechanism.Domain) ? parameters.CurrentDomain : spfMechanism.Domain, parameters), RecordType.Mx);
						if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
							return SpfQualifier.TempError;

						int mxCheckedCount = 0;

						foreach (DnsRecordBase dnsRecord in dnsMessage.AnswerRecords)
						{
							MxRecord mxRecord = dnsRecord as MxRecord;
							if (mxRecord != null)
							{
								if (++mxCheckedCount == 10)
									break;

								bool? isMxMatch = IsIpMatch(mxRecord.ExchangeDomainName, parameters.ClientAddress, spfMechanism.Prefix, spfMechanism.Prefix6);
								if (!isMxMatch.HasValue)
									return SpfQualifier.TempError;

								if (isMxMatch.Value)
								{
									return spfMechanism.Qualifier;
								}
							}
						}
						break;

					case SpfMechanismType.Ip4:
					case SpfMechanismType.Ip6:
						IPAddress compareAddress;
						if (IPAddress.TryParse(spfMechanism.Domain, out compareAddress))
						{
							if (spfMechanism.Prefix.HasValue)
							{
								if (parameters.ClientAddress.GetNetworkAddress(spfMechanism.Prefix.Value).Equals(compareAddress.GetNetworkAddress(spfMechanism.Prefix.Value)))
								{
									return spfMechanism.Qualifier;
								}
							}
							else if (parameters.ClientAddress.Equals(compareAddress))
							{
								return spfMechanism.Qualifier;
							}
						}
						else
						{
							return SpfQualifier.PermError;
						}

						break;

					case SpfMechanismType.Ptr:
						dnsMessage = DnsClient.Default.Resolve(parameters.ClientAddress.GetReverseLookupAddress(), RecordType.Ptr);
						if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
							return SpfQualifier.TempError;

						string ptrCompareName = String.IsNullOrEmpty(spfMechanism.Domain) ? parameters.CurrentDomain : spfMechanism.Domain;

						int ptrCheckedCount = 0;
						foreach (DnsRecordBase dnsRecord in dnsMessage.AnswerRecords)
						{
							PtrRecord ptrRecord = dnsRecord as PtrRecord;
							if (ptrRecord != null)
							{
								if (++ptrCheckedCount == 10)
									break;

								bool? isPtrMatch = IsIpMatch(ptrRecord.PointerDomainName, parameters.ClientAddress, 0, 0);
								if (isPtrMatch.HasValue && isPtrMatch.Value)
								{
									if (ptrRecord.PointerDomainName.Equals(ptrCompareName, StringComparison.InvariantCultureIgnoreCase) || (ptrRecord.PointerDomainName.EndsWith("." + ptrCompareName, StringComparison.InvariantCultureIgnoreCase)))
										return spfMechanism.Qualifier;
								}
							}
						}
						break;

					case SpfMechanismType.Exist:
						if (String.IsNullOrEmpty(spfMechanism.Domain))
							return SpfQualifier.PermError;

						dnsMessage = DnsClient.Default.Resolve(ExpandDomain(spfMechanism.Domain, parameters), RecordType.A);
						if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
							return SpfQualifier.TempError;

						if (dnsMessage.AnswerRecords.Count(record => (record.RecordType == RecordType.A)) > 0)
						{
							return spfMechanism.Qualifier;
						}
						break;

					case SpfMechanismType.Include:
						if (String.IsNullOrEmpty(spfMechanism.Domain))
							return SpfQualifier.PermError;

						string includeDomain = ExpandDomain(spfMechanism.Domain, parameters);
						switch (SpfRecord.CheckHost(includeDomain, new SpfCheckHostParameter(includeDomain, parameters)))
						{
							case SpfQualifier.Pass:
								return spfMechanism.Qualifier;

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
			}

			SpfModifier spfModifier = this as SpfModifier;
			if (spfModifier != null)
			{
				switch (spfModifier.Type)
				{
					case SpfModifierType.Redirect:
						if (String.IsNullOrEmpty(spfModifier.Domain))
							return SpfQualifier.PermError;

						string redirectDomain = ExpandDomain(spfModifier.Domain, parameters);
						return SpfRecord.CheckHost(redirectDomain, new SpfCheckHostParameter(redirectDomain, parameters));

					case SpfModifierType.Exp:
						break;

					default:
						return SpfQualifier.PermError;
				}
			}

			return SpfQualifier.None;
		}

		private static string ExpandDomain(string pattern, SpfCheckHostParameter parameters)
		{
			Regex regex = new Regex(@"(%%|%_|%-|%\{(?<letter>[slodiphcrtv])(?<count>\d*)(?<reverse>r?)(?<delimiter>[\.\-+,/=]*)})", RegexOptions.Compiled);

			return regex.Replace(pattern, delegate(Match match) { return ExpandMacro(match, parameters); });
		}

		private static string ExpandMacro(Match pattern, SpfCheckHostParameter parameters)
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
							letter = parameters.Sender;
							break;
						case "l":
							// no boundary check needed, sender is validated on start of CheckHost
							letter = parameters.Sender.Split('@')[0];
							break;
						case "o":
							// no boundary check needed, sender is validated on start of CheckHost
							letter = parameters.Sender.Split('@')[1];
							break;
						case "d":
							letter = parameters.CurrentDomain;
							break;
						case "i":
							letter = String.Join(".", parameters.ClientAddress.GetAddressBytes().Select(b => b.ToString()).ToArray());
							break;
						case "p":
							letter = parameters.ClientName;
							break;
						case "v":
							letter = (parameters.ClientAddress.AddressFamily == AddressFamily.InterNetworkV6) ? "ip6" : "in-addr";
							break;
						case "h":
							letter = parameters.HeloName;
							break;
						case "c":
							letter = parameters.ClientAddress.ToString();
							break;
						case "r":
							letter = System.Net.Dns.GetHostName();
							break;
						case "t":
							letter = ((int)(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) - DateTime.Now).TotalSeconds).ToString();
							break;
						default:
							return null;
					}

					// only letter
					if (pattern.Value.Length == 4)
						return letter;

					char[] delimiters = pattern.Groups["delimiter"].Value.ToCharArray();
					if ((delimiters == null) || (delimiters.Length == 0))
						delimiters = new char[] { '.' };

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

		private static bool? IsIpMatch(string domain, IPAddress ipAddress, int? prefix4, int? prefix6)
		{
			if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
			{
				return IsIp6Match(domain, ipAddress, prefix6);
			}
			else
			{
				return IsIp4Match(domain, ipAddress, prefix4);
			}
		}

		private static bool? IsIp4Match(string domain, IPAddress ipAddress, int? prefix4)
		{
			if (prefix4.HasValue)
			{
				ipAddress = ipAddress.GetNetworkAddress(prefix4.Value);
			}

			DnsMessage dnsMessage = DnsClient.Default.Resolve(domain, RecordType.A);
			if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
				return null;

			foreach (ARecord dnsRecord in dnsMessage.AnswerRecords.Where(record => record.RecordType == RecordType.A).Cast<ARecord>())
			{
				if (prefix4.HasValue)
				{
					if (ipAddress.Equals(dnsRecord.Address.GetNetworkAddress(prefix4.Value)))
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

		private static bool? IsIp6Match(string domain, IPAddress ipAddress, int? prefix6)
		{
			if (prefix6.HasValue)
			{
				ipAddress = ipAddress.GetNetworkAddress(prefix6.Value);
			}

			DnsMessage dnsMessage = DnsClient.Default.Resolve(domain, RecordType.Aaaa);
			if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
				return null;

			foreach (AaaaRecord dnsRecord in dnsMessage.AnswerRecords.Where(record => record.RecordType == RecordType.Aaaa).Cast<AaaaRecord>())
			{
				if (prefix6.HasValue)
				{
					if (ipAddress.Equals(dnsRecord.Address.GetNetworkAddress(prefix6.Value)))
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
		#endregion
	}
}
