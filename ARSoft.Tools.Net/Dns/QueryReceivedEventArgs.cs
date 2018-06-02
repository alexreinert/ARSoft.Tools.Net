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
using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns
{
    /// <inheritdoc />
    /// <summary>
    ///     Event arguments of <see cref="E:ARSoft.Tools.Net.Dns.DnsServer.QueryReceived" /> event.
    /// </summary>
    public class QueryReceivedEventArgs : EventArgs
    {
        internal QueryReceivedEventArgs(DnsMessageBase query, ProtocolType protocolType, IPEndPoint remoteEndpoint)
        {
            Query = query;
            ProtocolType = protocolType;
            RemoteEndpoint = remoteEndpoint;
        }

        /// <summary>
        ///     Original query, which the client provided
        /// </summary>
        public DnsMessageBase Query { get; }

        /// <summary>
        ///     Protocol used by the client
        /// </summary>
        public ProtocolType ProtocolType { get; }

        /// <summary>
        ///     Remote endpoint of the client
        /// </summary>
        public IPEndPoint RemoteEndpoint { get; }

        /// <summary>
        ///     The response, which should be sent to the client
        /// </summary>
        public DnsMessageBase Response { get; set; }
    }
}