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
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace ARSoft.Tools.Net.Dns
{
    /// <summary>
    ///   TLS Upstream server info
    /// </summary>
    public class TlsUpstreamServer
    {
        /// <summary>
        ///   Gets or sets upstream server authentication domain name
        /// </summary>
        public string AuthName { get; set; }

        /// <summary>
        ///   Gets or sets upstream server IP address
        /// </summary>
        public System.Net.IPAddress IPAddress { get; set; }

        /// <summary>
        ///   Gets or sets upstream server listening port, default is 853
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        ///   Gets or sets upstream server valid SPKI pinsets verified against the keys in the server certificate
        /// </summary>
        public List<TlsPubkeyPinningHash> Pinsets { get; set; }

        /// <summary>
        ///   Gets or sets upstream server valid TLS protocols, default is all Tls protocols
        /// </summary>
        public SslProtocols SslProtocols { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TlsUpstreamServer" /> class.
        /// </summary>
        public TlsUpstreamServer() : base()
        {
            this.Port = 853;
            this.SslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;
        }

        /// <summary>
        /// SslStream user certificate validation callback
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        public bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            if (this.Pinsets == null || this.Pinsets.Count == 0)
            {
                return false;
            }

            X509Certificate2 cert2 = certificate as X509Certificate2;
            Dictionary<string, string> dic = new Dictionary<string, string>();
            foreach (string dig in this.Pinsets.Select(p => p.Digest).Distinct().ToList())
            {
                dic[dig] = cert2.GetPublicKeyPinningHash(dig);
            }

            if (dic.Count == 0)
            {
                return false;
            }

            bool ret = false;

            foreach (var val in dic)
            {
                if (this.Pinsets.Any(p => p.Digest == val.Key && p.Hash == val.Value))
                {
                    ret = true;
                    break;
                }
            }

            return ret;
        }
    }
}
