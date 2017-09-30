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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public enum DnsSecAlgorithm : byte
	{
		RsaMd5 = 1, // RFC4034
		DiffieHellman = 2, // RFC2539
		DsaSha1 = 3, // RFC3755
		EllipticCurve = 4,
		RsaSha1 = 5, // RFC3755
		DsaNsec3Sha1 = 6, // RFC5155
		RsaSha1Nsec3Sha1 = 7, // RFC5155
		RsaSha256 = 8, // RFC5702
		RsaSha512 = 10, // RFC5702
		EccGost = 12, // RFC5933

		Indirect = 252, // RFC4034
		PrivateDns = 253, // RFC3755
		PrivateOid = 254, // RFC3755
	}
}