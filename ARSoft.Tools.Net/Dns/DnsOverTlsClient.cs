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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns.DynamicUpdate;

namespace ARSoft.Tools.Net.Dns
{
    /// <summary>
    ///   Provides a client for querying dns records through TLS
    /// </summary>
    public class DnsOverTlsClient : DnsOverTlsClientBase
    {
        /// <summary>
        ///   Returns a default instance of the DnsClient, which uses the configured dns servers of the executing computer and a
        ///   query timeout of 10 seconds.
        /// </summary>
        public static DnsOverTlsClient Default { get; private set; }

        static DnsOverTlsClient()
        {
            Default = new DnsOverTlsClient(GetLocalConfiguredDnsOverTlsServers(), 10000) { IsResponseValidationEnabled = true };
        }

        /// <summary>
        ///   Provides a new instance with custom dns server and query timeout
        /// </summary>
        /// <param name="dnsServer"> The IPAddress of the dns server to use </param>
        /// <param name="queryTimeout"> Query timeout in milliseconds </param>
        /// <param name="port"> Server port </param>
        public DnsOverTlsClient(TlsUpstreamServer dnsServer, int queryTimeout, int port = 853)
            : this(new List<TlsUpstreamServer> { dnsServer }, queryTimeout, port) {}

        /// <summary>
        ///   Provides a new instance with custom dns servers and query timeout
        /// </summary>
        /// <param name="dnsServers"> The IPAddresses of the dns servers to use </param>
        /// <param name="queryTimeout"> Query timeout in milliseconds </param>
        /// <param name="port"> Server port </param>
        public DnsOverTlsClient(IEnumerable<TlsUpstreamServer> dnsServers, int queryTimeout, int port = 853)
            : base(dnsServers, queryTimeout, port)
        {
        }

        protected override int MaximumQueryMessageSize => 512;

        /// <summary>
        ///   Queries a dns server for specified records.
        /// </summary>
        /// <param name="name"> Domain, that should be queried </param>
        /// <param name="recordType"> Type the should be queried </param>
        /// <param name="recordClass"> Class the should be queried </param>
        /// <param name="options"> Options for the query </param>
        /// <returns> The complete response of the dns server </returns>
        public DnsMessage Resolve(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, DnsQueryOptions options = null)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name), "Name must be provided");

            DnsMessage message = new DnsMessage() { IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true, IsEDnsEnabled = true };

            if (options == null)
            {
                message.IsRecursionDesired = true;
                message.IsEDnsEnabled = true;
            }
            else
            {
                message.IsRecursionDesired = options.IsRecursionDesired;
                message.IsCheckingDisabled = options.IsCheckingDisabled;
                message.EDnsOptions = options.EDnsOptions;
            }

            message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

            return SendMessage(message);
        }

        /// <summary>
        ///   Queries a dns server for specified records as an asynchronous operation.
        /// </summary>
        /// <param name="name"> Domain, that should be queried </param>
        /// <param name="recordType"> Type the should be queried </param>
        /// <param name="recordClass"> Class the should be queried </param>
        /// <param name="options"> Options for the query </param>
        /// <param name="token"> The token to monitor cancellation requests </param>
        /// <returns> The complete response of the dns server </returns>
        public Task<DnsMessage> ResolveAsync(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, DnsQueryOptions options = null, CancellationToken token = default(CancellationToken))
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name), "Name must be provided");

            DnsMessage message = new DnsMessage() { IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true, IsEDnsEnabled = true };

            if (options == null)
            {
                message.IsRecursionDesired = true;
                message.IsEDnsEnabled = true;
            }
            else
            {
                message.IsRecursionDesired = options.IsRecursionDesired;
                message.IsCheckingDisabled = options.IsCheckingDisabled;
                message.EDnsOptions = options.EDnsOptions;
            }

            message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

            return SendMessageAsync(message, token);
        }

        /// <summary>
        ///   Send a custom message to the dns server and returns the answer.
        /// </summary>
        /// <param name="message"> Message, that should be send to the dns server </param>
        /// <returns> The complete response of the dns server </returns>
        public DnsMessage SendMessage(DnsMessage message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            if ((message.Questions == null) || (message.Questions.Count == 0))
                throw new ArgumentException("At least one question must be provided", nameof(message));

            return SendMessage<DnsMessage>(message);
        }

        /// <summary>
        ///   Send a custom message to the dns server and returns the answer as an asynchronous operation.
        /// </summary>
        /// <param name="message"> Message, that should be send to the dns server </param>
        /// <param name="token"> The token to monitor cancellation requests </param>
        /// <returns> The complete response of the dns server </returns>
        public Task<DnsMessage> SendMessageAsync(DnsMessage message, CancellationToken token = default(CancellationToken))
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            if ((message.Questions == null) || (message.Questions.Count == 0))
                throw new ArgumentException("At least one question must be provided", nameof(message));

            return SendMessageAsync<DnsMessage>(message, token);
        }

        /// <summary>
        ///   Send an dynamic update to the dns server and returns the answer.
        /// </summary>
        /// <param name="message"> Update, that should be send to the dns server </param>
        /// <returns> The complete response of the dns server </returns>
        public DnsUpdateMessage SendUpdate(DnsUpdateMessage message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            if (message.ZoneName == null)
                throw new ArgumentException("Zone name must be provided", nameof(message));

            return SendMessage(message);
        }

        /// <summary>
        ///   Send an dynamic update to the dns server and returns the answer as an asynchronous operation.
        /// </summary>
        /// <param name="message"> Update, that should be send to the dns server </param>
        /// <param name="token"> The token to monitor cancellation requests </param>
        /// <returns> The complete response of the dns server </returns>
        public Task<DnsUpdateMessage> SendUpdateAsync(DnsUpdateMessage message, CancellationToken token = default(CancellationToken))
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            if (message.ZoneName == null)
                throw new ArgumentException("Zone name must be provided", nameof(message));

            return SendMessageAsync(message, token);
        }

        /// <summary>
        ///   Returns a list of the local configured DNS servers.
        /// </summary>
        /// <returns></returns>
        public static List<TlsUpstreamServer> GetLocalConfiguredDnsOverTlsServers()
        {
            List<TlsUpstreamServer> res = new List<TlsUpstreamServer>();

            // TODO: Some method to get local configured DNS-over-TLS servers

            if (res.Count == 0)
            {
                res.Add(new TlsUpstreamServer()
                {
                    AuthName = "dnsovertls.sinodun.com",
                    IPAddress = System.Net.IPAddress.Parse("145.100.185.15"),
                    Pinsets = new List<TlsPubkeyPinningHash>() { new TlsPubkeyPinningHash() { Digest = "sha256", Hash = "62lKu9HsDVbyiPenApnc4sfmSYTHOVfFgL3pyB+cBL4=" } },
                });

                res.Add(new TlsUpstreamServer()
                {
                    AuthName = "dnsovertls.sinodun.com",
                    IPAddress = System.Net.IPAddress.Parse("2001:610:1:40ba:145:100:185:15"),
                    Pinsets = new List<TlsPubkeyPinningHash>() { new TlsPubkeyPinningHash() { Digest = "sha256", Hash = "62lKu9HsDVbyiPenApnc4sfmSYTHOVfFgL3pyB+cBL4=" } },
                });

                res.Add(new TlsUpstreamServer()
                {
                    AuthName = "dnsovertls1.sinodun.com",
                    IPAddress = System.Net.IPAddress.Parse("145.100.185.16"),
                    Pinsets = new List<TlsPubkeyPinningHash>() { new TlsPubkeyPinningHash() { Digest = "sha256", Hash = "cE2ecALeE5B+urJhDrJlVFmf38cJLAvqekONvjvpqUA=" } },
                });

                res.Add(new TlsUpstreamServer()
                {
                    AuthName = "dnsovertls1.sinodun.com",
                    IPAddress = System.Net.IPAddress.Parse("2001:610:1:40ba:145:100:185:16"),
                    Pinsets = new List<TlsPubkeyPinningHash>() { new TlsPubkeyPinningHash() { Digest = "sha256", Hash = "cE2ecALeE5B+urJhDrJlVFmf38cJLAvqekONvjvpqUA=" } },
                });

                res.Add(new TlsUpstreamServer()
                {
                    AuthName = "getdnsapi.net",
                    IPAddress = System.Net.IPAddress.Parse("185.49.141.37"),
                    Pinsets = new List<TlsPubkeyPinningHash>() { new TlsPubkeyPinningHash() { Digest = "sha256", Hash = "foxZRnIh9gZpWnl+zEiKa0EJ2rdCGroMWm02gaxSc9S=" } },
                });

                res.Add(new TlsUpstreamServer()
                {
                    AuthName = "getdnsapi.net",
                    IPAddress = System.Net.IPAddress.Parse("2a04:b900:0:100::37"),
                    Pinsets = new List<TlsPubkeyPinningHash>() { new TlsPubkeyPinningHash() { Digest = "sha256", Hash = "foxZRnIh9gZpWnl+zEiKa0EJ2rdCGroMWm02gaxSc9S=" } },
                });
            }

            return res.OrderBy(x => x.IPAddress.AddressFamily == AddressFamily.InterNetworkV6 ? 1 : 0).ToList();
        }
    }
}
