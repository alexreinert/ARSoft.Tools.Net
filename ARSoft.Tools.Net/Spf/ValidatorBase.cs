﻿#region Copyright and License

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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;
using ARSoft.Tools.Net.Dns.DnsRecord;
using ARSoft.Tools.Net.Dns.Resolver;

namespace ARSoft.Tools.Net.Spf
{
    /// <summary>
    ///     Base implementation of a validator for SPF and SenderID records
    /// </summary>
    /// <typeparam name="T"> Type of the record </typeparam>
    public abstract class ValidatorBase<T>
        where T : SpfRecordBase
    {
        // ReSharper disable once StaticMemberInGenericType
        private static readonly Regex _parseMacroRegex =
            new Regex(@"(%%|%_|%-|%\{(?<letter>[slodiphcrtv])(?<count>\d*)(?<reverse>r?)(?<delimiter>[\.\-+,/=]*)})",
                RegexOptions.Compiled);


        /// <summary>
        ///     DnsResolver which is used for DNS lookups
        ///     <para>Default is a Stub DNS resolver using the local configured upstream servers</para>
        /// </summary>
        public IDnsResolver DnsResolver { get; set; } = new DnsStubResolver();

        /// <summary>
        ///     Domain name which was used in HELO/EHLO
        /// </summary>
        public DomainName HeloDomain { get; set; }

        /// <summary>
        ///     IP address of the computer validating the record
        ///     <para>Default is the first IP the computer</para>
        /// </summary>
        public IPAddress LocalIp { get; set; }

        /// <summary>
        ///     Name of the computer validating the record
        ///     <para>Default is the computer name</para>
        /// </summary>
        public DomainName LocalDomain { get; set; }

        /// <summary>
        ///     The maximum number of DNS lookups allowed
        ///     <para>Default is 20</para>
        /// </summary>
        public int DnsLookupLimit { get; set; } = 20;

        protected abstract Task<LoadRecordResult> LoadRecordsAsync(DomainName domain, CancellationToken token);

        /// <summary>
        ///     Validates the record(s)
        /// </summary>
        /// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
        /// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
        /// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
        /// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
        /// <returns> The result of the evaluation </returns>
        public ValidationResult CheckHost(IPAddress ip, DomainName domain, string sender,
            bool expandExplanation = false)
        {
            var result = CheckHostInternalAsync(ip, domain, sender, expandExplanation, new State(),
                default(CancellationToken));
            result.Wait();

            return result.Result;
        }

        /// <summary>
        ///     Validates the record(s)
        /// </summary>
        /// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
        /// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
        /// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
        /// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
        /// <returns> The result of the evaluation </returns>
        public ValidationResult CheckHost(IPAddress ip, string domain, string sender, bool expandExplanation = false) =>
            CheckHost(ip, DomainName.Parse(domain), sender, expandExplanation);

        /// <summary>
        ///     Validates the record(s)
        /// </summary>
        /// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
        /// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
        /// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
        /// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
        /// <param name="token"> The token to monitor cancellation requests </param>
        /// <returns> The result of the evaluation </returns>
        public Task<ValidationResult> CheckHostAsync(IPAddress ip, DomainName domain, string sender,
            bool expandExplanation = false, CancellationToken token = default(CancellationToken)) =>
            CheckHostInternalAsync(ip, domain, sender, expandExplanation, new State(), token);

        /// <summary>
        ///     Validates the record(s)
        /// </summary>
        /// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
        /// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
        /// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
        /// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
        /// <param name="token"> The token to monitor cancellation requests </param>
        /// <returns> The result of the evaluation </returns>
        public Task<ValidationResult> CheckHostAsync(IPAddress ip, string domain, string sender,
            bool expandExplanation = false, CancellationToken token = default(CancellationToken)) =>
            CheckHostAsync(ip, DomainName.Parse(domain), sender, expandExplanation, token);

        private async Task<ValidationResult> CheckHostInternalAsync(IPAddress ip, DomainName domain, string sender,
            bool expandExplanation, State state, CancellationToken token)
        {
            if (domain == null || domain.Equals(DomainName.Root))
                return new ValidationResult {Result = SpfQualifier.None, Explanation = string.Empty};

            if (string.IsNullOrEmpty(sender))
                sender = "postmaster@unknown";
            else if (!sender.Contains('@')) sender = "postmaster@" + sender;

            var loadResult = await LoadRecordsAsync(domain, token);

            if (!loadResult.CouldBeLoaded)
                return new ValidationResult {Result = loadResult.ErrorResult, Explanation = string.Empty};

            var record = loadResult.Record;

            if (record.Terms == null || record.Terms.Count == 0)
                return new ValidationResult {Result = SpfQualifier.Neutral, Explanation = string.Empty};

            if (record.Terms.OfType<SpfModifier>().GroupBy(m => m.Type)
                .Where(g => g.Key == SpfModifierType.Exp || g.Key == SpfModifierType.Redirect).Any(g => g.Count() > 1))
                return new ValidationResult {Result = SpfQualifier.PermError, Explanation = string.Empty};

            var result = new ValidationResult {Result = loadResult.ErrorResult};

            #region Evaluate mechanism

            foreach (var mechanism in record.Terms.OfType<SpfMechanism>())
            {
                if (state.DnsLookupCount > DnsLookupLimit)
                    return new ValidationResult {Result = SpfQualifier.PermError, Explanation = string.Empty};

                var qualifier = await CheckMechanismAsync(mechanism, ip, domain, sender, state, token);

                if (qualifier == SpfQualifier.None) continue;
                result.Result = qualifier;
                break;
            }

            #endregion

            #region Evaluate modifiers

            if (result.Result == SpfQualifier.None)
            {
                var redirectModifier = record.Terms.OfType<SpfModifier>()
                    .FirstOrDefault(m => m.Type == SpfModifierType.Redirect);
                if (redirectModifier != null)
                {
                    if (++state.DnsLookupCount > 10)
                        return new ValidationResult {Result = SpfQualifier.PermError, Explanation = string.Empty};

                    var redirectDomain = await ExpandDomainAsync(redirectModifier.Domain ?? string.Empty, ip, domain,
                        sender, token);

                    if (redirectDomain == null || redirectDomain == DomainName.Root || redirectDomain.Equals(domain))
                        result.Result = SpfQualifier.PermError;
                    else
                    {
                        result = await CheckHostInternalAsync(ip, redirectDomain, sender, expandExplanation, state,
                            token);

                        if (result.Result == SpfQualifier.None)
                            result.Result = SpfQualifier.PermError;
                    }
                }
            }
            else if (result.Result == SpfQualifier.Fail && expandExplanation)
            {
                var expModifier = record.Terms.OfType<SpfModifier>().FirstOrDefault(m => m.Type == SpfModifierType.Exp);
                if (expModifier != null)
                {
                    var target = await ExpandDomainAsync(expModifier.Domain, ip, domain, sender, token);

                    if (target == null || target.Equals(DomainName.Root))
                        result.Explanation = string.Empty;
                    else
                    {
                        var dnsResult = await ResolveDnsAsync<TxtRecord>(target, RecordType.Txt, token);
                        if (dnsResult != null && dnsResult.ReturnCode == ReturnCode.NoError)
                        {
                            var txtRecord = dnsResult.Records.FirstOrDefault();
                            if (txtRecord != null)
                                result.Explanation =
                                    await ExpandMacroAsync(txtRecord.TextData, ip, domain, sender, token);
                        }
                    }
                }
            }

            #endregion

            if (result.Result == SpfQualifier.None)
                result.Result = SpfQualifier.Neutral;

            return result;
        }

        private async Task<SpfQualifier> CheckMechanismAsync(SpfMechanism mechanism, IPAddress ip, DomainName domain,
            string sender, State state, CancellationToken token)
        {
            switch (mechanism.Type)
            {
                case SpfMechanismType.All:
                    return mechanism.Qualifier;

                case SpfMechanismType.A:
                    if (++state.DnsLookupCount > 10)
                        return SpfQualifier.PermError;

                    var aMechanismDomain = string.IsNullOrEmpty(mechanism.Domain)
                        ? domain
                        : await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, token);

                    var isAMatch =
                        await IsIpMatchAsync(aMechanismDomain, ip, mechanism.Prefix, mechanism.Prefix6, token);
                    if (!isAMatch.HasValue)
                        return SpfQualifier.TempError;

                    if (isAMatch.Value) return mechanism.Qualifier;
                    break;

                case SpfMechanismType.Mx:
                    if (++state.DnsLookupCount > 10)
                        return SpfQualifier.PermError;

                    var mxMechanismDomain = string.IsNullOrEmpty(mechanism.Domain)
                        ? domain
                        : await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, token);

                    var dnsMxResult = await ResolveDnsAsync<MxRecord>(mxMechanismDomain, RecordType.Mx, token);
                    if (dnsMxResult == null || dnsMxResult.ReturnCode != ReturnCode.NoError &&
                        dnsMxResult.ReturnCode != ReturnCode.NxDomain)
                        return SpfQualifier.TempError;

                    var mxCheckedCount = 0;

                    foreach (var mxRecord in dnsMxResult.Records)
                    {
                        if (++mxCheckedCount == 10)
                            break;

                        var isMxMatch = await IsIpMatchAsync(mxRecord.ExchangeDomainName, ip, mechanism.Prefix,
                            mechanism.Prefix6, token);
                        if (!isMxMatch.HasValue)
                            return SpfQualifier.TempError;

                        if (isMxMatch.Value) return mechanism.Qualifier;
                    }

                    break;

                case SpfMechanismType.Ip4:
                case SpfMechanismType.Ip6:
                    if (IPAddress.TryParse(mechanism.Domain, out var compareAddress))
                    {
                        if (ip.AddressFamily != compareAddress.AddressFamily)
                            return SpfQualifier.None;

                        if (mechanism.Prefix.HasValue)
                        {
                            if (mechanism.Prefix.Value < 0 || mechanism.Prefix.Value >
                                (compareAddress.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32))
                                return SpfQualifier.PermError;

                            if (ip.GetNetworkAddress(mechanism.Prefix.Value)
                                .Equals(compareAddress.GetNetworkAddress(mechanism.Prefix.Value)))
                                return mechanism.Qualifier;
                        }
                        else if (ip.Equals(compareAddress)) return mechanism.Qualifier;
                    }
                    else
                        return SpfQualifier.PermError;

                    break;

                case SpfMechanismType.Ptr:
                    if (++state.DnsLookupCount > 10)
                        return SpfQualifier.PermError;

                    var dnsPtrResult =
                        await ResolveDnsAsync<PtrRecord>(ip.GetReverseLookupDomain(), RecordType.Ptr, token);
                    if (dnsPtrResult == null || dnsPtrResult.ReturnCode != ReturnCode.NoError &&
                        dnsPtrResult.ReturnCode != ReturnCode.NxDomain)
                        return SpfQualifier.TempError;

                    var ptrMechanismDomain = string.IsNullOrEmpty(mechanism.Domain)
                        ? domain
                        : await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, token);

                    var ptrCheckedCount = 0;
                    foreach (var ptrRecord in dnsPtrResult.Records)
                    {
                        if (++ptrCheckedCount == 10)
                            break;

                        var isPtrMatch = await IsIpMatchAsync(ptrRecord.PointerDomainName, ip, 0, 0, token);
                        if (isPtrMatch.HasValue && isPtrMatch.Value)
                            if (ptrRecord.PointerDomainName.Equals(ptrMechanismDomain) ||
                                ptrRecord.PointerDomainName.IsSubDomainOf(ptrMechanismDomain))
                                return mechanism.Qualifier;
                    }

                    break;

                case SpfMechanismType.Exists:
                    if (++state.DnsLookupCount > 10)
                        return SpfQualifier.PermError;

                    if (string.IsNullOrEmpty(mechanism.Domain))
                        return SpfQualifier.PermError;

                    var existsMechanismDomain = string.IsNullOrEmpty(mechanism.Domain)
                        ? domain
                        : await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, token);

                    var dnsAResult = await ResolveDnsAsync<ARecord>(existsMechanismDomain, RecordType.A, token);
                    if (dnsAResult == null || dnsAResult.ReturnCode != ReturnCode.NoError &&
                        dnsAResult.ReturnCode != ReturnCode.NxDomain)
                        return SpfQualifier.TempError;

                    if (dnsAResult.Records.Count(record => record.RecordType == RecordType.A) > 0)
                        return mechanism.Qualifier;
                    break;

                case SpfMechanismType.Include:
                    if (++state.DnsLookupCount > 10)
                        return SpfQualifier.PermError;

                    if (string.IsNullOrEmpty(mechanism.Domain))
                        return SpfQualifier.PermError;

                    var includeMechanismDomain = string.IsNullOrEmpty(mechanism.Domain)
                        ? domain
                        : await ExpandDomainAsync(mechanism.Domain, ip, domain, sender, token);

                    if (includeMechanismDomain.Equals(domain))
                        return SpfQualifier.PermError;

                    var includeResult =
                        await CheckHostInternalAsync(ip, includeMechanismDomain, sender, false, state, token);
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

        private Task<bool?> IsIpMatchAsync(DomainName domain, IPAddress ipAddress, int? prefix4, int? prefix6,
            CancellationToken token)
        {
            if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (prefix6.HasValue)
                    ipAddress = ipAddress.GetNetworkAddress(prefix6.Value);

                return IsIpMatchAsync<AaaaRecord>(domain, ipAddress, prefix6, RecordType.Aaaa, token);
            }

            if (prefix4.HasValue)
                ipAddress = ipAddress.GetNetworkAddress(prefix4.Value);

            return IsIpMatchAsync<ARecord>(domain, ipAddress, prefix4, RecordType.A, token);
        }

        private async Task<bool?> IsIpMatchAsync<TRecord>(DomainName domain, IPAddress ipAddress, int? prefix,
            RecordType recordType, CancellationToken token)
            where TRecord : DnsRecordBase, IAddressRecord
        {
            var dnsResult = await ResolveDnsAsync<TRecord>(domain, recordType, token);
            if (dnsResult == null || dnsResult.ReturnCode != ReturnCode.NoError &&
                dnsResult.ReturnCode != ReturnCode.NxDomain)
                return null;

            foreach (var dnsRecord in dnsResult.Records)
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

            return false;
        }

        protected async Task<DnsResolveResult<TRecord>> ResolveDnsAsync<TRecord>(DomainName domain,
            RecordType recordType, CancellationToken token)
            where TRecord : DnsRecordBase
        {
            try
            {
                var records = await DnsResolver.ResolveAsync<TRecord>(domain, recordType, token: token);
                return new DnsResolveResult<TRecord>(ReturnCode.NoError, records);
            }
            catch
            {
                return new DnsResolveResult<TRecord>(ReturnCode.ServerFailure, null);
            }
        }

        private async Task<DomainName> ExpandDomainAsync(string pattern, IPAddress ip, DomainName domain, string sender,
            CancellationToken token)
        {
            var expanded = await ExpandMacroAsync(pattern, ip, domain, sender, token);

            return string.IsNullOrEmpty(expanded) ? DomainName.Root : DomainName.Parse(expanded);
        }

        private async Task<string> ExpandMacroAsync(string pattern, IPAddress ip, DomainName domain, string sender,
            CancellationToken token)
        {
            if (string.IsNullOrEmpty(pattern))
                return string.Empty;

            var match = _parseMacroRegex.Match(pattern);
            if (!match.Success) return pattern;

            var sb = new StringBuilder();
            var pos = 0;
            do
            {
                if (match.Index != pos) sb.Append(pattern, pos, match.Index - pos);
                pos = match.Index + match.Length;
                sb.Append(await ExpandMacroAsync(match, ip, domain, sender, token));
                match = match.NextMatch();
            }
            while (match.Success);

            if (pos < pattern.Length) sb.Append(pattern, pos, pattern.Length - pos);

            return sb.ToString();
        }

        private async Task<string> ExpandMacroAsync(Match pattern, IPAddress ip, DomainName domain, string sender,
            CancellationToken token)
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
                            letter = domain.ToString();
                            break;
                        case "i":
                            letter = string.Join(".", ip.GetAddressBytes().Select(b => b.ToString()));
                            break;
                        case "p":
                            letter = "unknown";

                            var dnsResult =
                                await ResolveDnsAsync<PtrRecord>(ip.GetReverseLookupDomain(), RecordType.Ptr, token);
                            if (dnsResult == null || dnsResult.ReturnCode != ReturnCode.NoError &&
                                dnsResult.ReturnCode != ReturnCode.NxDomain) break;

                            var ptrCheckedCount = 0;
                            foreach (var ptrRecord in dnsResult.Records)
                            {
                                if (++ptrCheckedCount == 10)
                                    break;

                                var isPtrMatch = await IsIpMatchAsync(ptrRecord.PointerDomainName, ip, 0, 0, token);
                                if (!isPtrMatch.HasValue || !isPtrMatch.Value) continue;
                                if (letter == "unknown" || ptrRecord.PointerDomainName.IsSubDomainOf(domain))
                                    letter = ptrRecord.PointerDomainName.ToString();
                                else if (ptrRecord.PointerDomainName.Equals(domain))
                                {
                                    // ptr equal domain --> best match, use it
                                    letter = ptrRecord.PointerDomainName.ToString();
                                    break;
                                }
                            }

                            break;
                        case "v":
                            letter = ip.AddressFamily == AddressFamily.InterNetworkV6 ? "ip6" : "in-addr";
                            break;
                        case "h":
                            letter = HeloDomain?.ToString() ?? "unknown";
                            break;
                        case "c":
                            var address =
                                LocalIp
                                ?? NetworkInterface.GetAllNetworkInterfaces()
                                    .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                                    .Select(u => u.Address)
                                    .FirstOrDefault(a => a.AddressFamily == ip.AddressFamily)
                                ?? (ip.AddressFamily == AddressFamily.InterNetwork
                                    ? IPAddress.Loopback
                                    : IPAddress.IPv6Loopback);
                            letter = address.ToString();
                            break;
                        case "r":
                            letter = LocalDomain?.ToString() ?? System.Net.Dns.GetHostName();
                            break;
                        case "t":
                            letter = ((int) (new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) - DateTime.Now)
                                .TotalSeconds).ToString();
                            break;
                        default:
                            return null;
                    }

                    // only letter
                    if (pattern.Value.Length == 4)
                        return letter;

                    var delimiters = pattern.Groups["delimiter"].Value.ToCharArray();
                    if (delimiters.Length == 0)
                        delimiters = new[] {'.'};

                    var parts = letter.Split(delimiters);

                    if (pattern.Groups["reverse"].Value == "r")
                        parts = parts.Reverse().ToArray();

                    var count = int.MaxValue;
                    if (!string.IsNullOrEmpty(pattern.Groups["count"].Value))
                        count = int.Parse(pattern.Groups["count"].Value);

                    if (count < 1)
                        return null;

                    count = Math.Min(count, parts.Length);

                    return string.Join(".", parts, parts.Length - count, count);
            }
        }

        protected class State
        {
            public int DnsLookupCount { get; set; }
        }

        protected class LoadRecordResult
        {
            public bool CouldBeLoaded { get; internal set; }
            public T Record { get; internal set; }
            public SpfQualifier ErrorResult { get; internal set; }
        }

        protected class DnsResolveResult<TRecord>
            where TRecord : DnsRecordBase
        {
            public DnsResolveResult(ReturnCode returnCode, List<TRecord> records)
            {
                ReturnCode = returnCode;
                Records = records;
            }

            public ReturnCode ReturnCode { get; }
            public List<TRecord> Records { get; }
        }
    }
}