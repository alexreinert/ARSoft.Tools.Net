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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ARSoft.Tools.Net.Dns
{
    public abstract class DnsOverTlsClientBase : DnsClientBase
    {
        private static readonly SecureRandom _secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

        private readonly List<TlsUpstreamServer> _tlsservers;
        private readonly bool _isAnyServerMulticast;
        private readonly int _port;

        internal DnsOverTlsClientBase(IEnumerable<TlsUpstreamServer> servers, int queryTimeout, int port) : base(servers.Select(s => s.IPAddress).ToList(), queryTimeout, port)
        {
            _tlsservers = servers.OrderBy(s => s.IPAddress.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ToList();
            _isAnyServerMulticast = _tlsservers.Any(s => s.IPAddress.IsMulticast());
            _port = port;
        }

        /// <summary>
        ///   Gets or sets a value indicationg whether queries can be sent using TCP.
        /// </summary>
        public new bool IsTcpEnabled
        {
            get { return true; }
        }

        /// <summary>
        ///   Gets or sets a value indicationg whether queries can be sent using UDP.
        /// </summary>
        public new bool IsUdpEnabled
        {
            get { return false; }
        }

        protected override byte[] QueryByTcp(IPAddress nameServer, int port, byte[] messageData, int messageLength, ref TcpClient tcpClient, ref System.IO.Stream tlsStream, out IPAddress responderAddress, out int responderPort)
        {
            responderAddress = nameServer;
            responderPort = port == 0 ? _port : port;

            if (!IsTcpEnabled)
                return null;

            IPEndPoint endPoint = new IPEndPoint(nameServer, port == 0 ? _port : port);

            IPAddress unferResponderAddress = responderAddress;
            int unferResponderPort = responderPort;
            TlsUpstreamServer tlsServer = _tlsservers.Where(t => t.IPAddress == unferResponderAddress && t.Port == unferResponderPort).FirstOrDefault();
            if (tlsServer == null)
            {
                Trace.TraceError("Error on dns query: invalid TLS upstream server");
                return null;
            }

            try
            {
                if (tcpClient == null || (this.IsReuseTcpEnabled && !tcpClient.IsConnected()))
                {
                    tcpClient = new TcpClient(nameServer.AddressFamily)
                    {
                        ReceiveTimeout = QueryTimeout,
                        SendTimeout = QueryTimeout
                    };

                    if (!tcpClient.TryConnect(endPoint, QueryTimeout))
                        return null;

                    SslStream sslStream = new SslStream(tcpClient.GetStream(), true, new RemoteCertificateValidationCallback(tlsServer.ValidateRemoteCertificate));
                    tlsStream = sslStream;
                    try
                    {
                        sslStream.AuthenticateAsClient(tlsServer.AuthName ?? string.Empty, new X509CertificateCollection(), tlsServer.SslProtocols, false);
                    }
                    catch (Exception)
                    {
                    }

                    if (!sslStream.IsAuthenticated)
                    {
                        Trace.TraceError("Error on dns query: invalid TLS upstream server certificate");
                        if (this.IsReuseTcpEnabled)
                        {
                            try
                            {
                                tlsStream.Dispose();
                                tcpClient.Close();
                            }
                            catch (Exception)
                            {
                            }
                        }

                        return null;
                    }
                }

                int tmp = 0;
                byte[] lengthBuffer = new byte[2];

                if (messageLength > 0)
                {
                    DnsMessageBase.EncodeUShort(lengthBuffer, ref tmp, (ushort)messageLength);

                    tlsStream.Write(lengthBuffer, 0, 2);
                    tlsStream.Write(messageData, 0, messageLength);
                }

                if (!TryRead(tcpClient, tlsStream, lengthBuffer, 2))
                    return null;

                tmp = 0;
                int length = DnsMessageBase.ParseUShort(lengthBuffer, ref tmp);

                byte[] resultData = new byte[length];

                return TryRead(tcpClient, tlsStream, resultData, length) ? resultData : null;
            }
            catch (Exception e)
            {
                Trace.TraceError("Error on dns query: " + e);
                return null;
            }
        }

        protected async override Task<QueryResponse> QueryByTcpAsync(IPAddress nameServer, int port, byte[] messageData, int messageLength, TcpClient tcpClient, System.IO.Stream tlsStream, CancellationToken token)
        {
            if (!IsTcpEnabled)
                return null;
            int responderPort = port == 0 ? _port : port;

            TlsUpstreamServer tlsServer = _tlsservers.Where(t => t.IPAddress == nameServer && t.Port == responderPort).FirstOrDefault();
            if (tlsServer == null)
            {
                Trace.TraceError("Error on dns query: invalid TLS upstream server");
                return null;
            }

            string reusableMapKey = string.Concat(nameServer, port);
            if (tcpClient == null && this.IsReuseTcpEnabled)
            {
                if (!this.reusableTcp.ContainsKey(reusableMapKey))
                {
                    this.reusableTcp[reusableMapKey] = new ReusableTcpConnection();
                }

                ReusableTcpConnection reuse = this.reusableTcp[reusableMapKey];
                tcpClient = reuse.Client;
                tlsStream = reuse.Stream;
                this.reusableTcp[reusableMapKey].LastUsed = DateTime.UtcNow;
            }

            try
            {
                if (tcpClient == null || (this.IsReuseTcpEnabled && !tcpClient.IsConnected()))
                {
                    tcpClient = new TcpClient(nameServer.AddressFamily)
                    {
                        ReceiveTimeout = QueryTimeout,
                        SendTimeout = QueryTimeout
                    };

                    if (!await tcpClient.TryConnectAsync(nameServer, responderPort, QueryTimeout, token))
                    {
                        return null;
                    }

                    SslStream sslStream = new SslStream(tcpClient.GetStream(), true, new RemoteCertificateValidationCallback(tlsServer.ValidateRemoteCertificate));
                    tlsStream = sslStream;
                    try
                    {
                        sslStream.AuthenticateAsClient(tlsServer.AuthName ?? string.Empty, new X509CertificateCollection(), tlsServer.SslProtocols, false);
                    }
                    catch (Exception)
                    {
                    }

                    if (!sslStream.IsAuthenticated)
                    {
                        Trace.TraceError("Error on dns query: invalid TLS upstream server certificate");
                        if (this.IsReuseTcpEnabled)
                        {
                            try
                            {
                                tlsStream.Dispose();
                                tcpClient.Close();
                            }
                            catch (Exception)
                            {
                            }
                        }

                        return null;
                    }
                }

                int tmp = 0;
                byte[] lengthBuffer = new byte[2];

                if (messageLength > 0)
                {
                    DnsMessageBase.EncodeUShort(lengthBuffer, ref tmp, (ushort)messageLength);

                    await tlsStream.WriteAsync(lengthBuffer, 0, 2, token);
                    await tlsStream.WriteAsync(messageData, 0, messageLength, token);
                }

                if (!await TryReadAsync(tcpClient, tlsStream, lengthBuffer, 2, token))
                    return null;

                tmp = 0;
                int length = DnsMessageBase.ParseUShort(lengthBuffer, ref tmp);

                byte[] resultData = new byte[length];

                return await TryReadAsync(tcpClient, tlsStream, resultData, length, token) ? new QueryResponse(resultData, nameServer, tcpClient, tlsStream, responderPort) : null;
            }
            catch (Exception e)
            {
                Trace.TraceError("Error on dns query: " + e);
                return null;
            }
        }

        internal override List<DnsClientEndpointInfo> GetEndpointInfos()
        {
            List<DnsClientEndpointInfo> endpointInfos;
            if (_isAnyServerMulticast)
            {
                var localIPs = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.SupportsMulticast && (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => a.Address))
                    .Where(a => !IPAddress.IsLoopback(a) && ((a.AddressFamily == AddressFamily.InterNetwork) || a.IsIPv6LinkLocal))
                    .ToList();

                endpointInfos = _tlsservers
                    .SelectMany(
                        s =>
                        {
                            if (s.IPAddress.IsMulticast())
                            {
                                return localIPs
                                    .Where(l => l.AddressFamily == s.IPAddress.AddressFamily)
                                    .Select(
                                        l => new DnsClientEndpointInfo
                                        {
                                            IsMulticast = true,
                                            ServerAddress = s.IPAddress,
                                            LocalAddress = l,
                                            ServerPort = s.Port,
                                        });
                            }
                            else
                            {
                                return new[]
                                {
                                    new DnsClientEndpointInfo
                                    {
                                        IsMulticast = false,
                                        ServerAddress = s.IPAddress,
                                        LocalAddress = s.IPAddress.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any,
                                        ServerPort = s.Port,
                                    }
                                };
                            }
                        }).ToList();
            }
            else
            {
                endpointInfos = _tlsservers
                    .Where(x => IsIPv6Enabled || (x.IPAddress.AddressFamily == AddressFamily.InterNetwork))
                    .Select(
                        s => new DnsClientEndpointInfo
                        {
                            IsMulticast = false,
                            ServerAddress = s.IPAddress,
                            LocalAddress = s.IPAddress.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any,
                            ServerPort = s.Port,
                        }
                    ).ToList();
            }
            return endpointInfos;
        }
    }
}
