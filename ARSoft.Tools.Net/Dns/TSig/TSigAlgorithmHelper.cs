#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;

namespace ARSoft.Tools.Net.Dns
{
	// ReSharper disable once InconsistentNaming
	internal class TSigAlgorithmHelper
	{
		public static DomainName GetDomainName(TSigAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case TSigAlgorithm.Md5:
					return DomainName.Parse("hmac-md5.sig-alg.reg.int");
				case TSigAlgorithm.Sha1:
					return DomainName.Parse("hmac-sha1");
				case TSigAlgorithm.Sha224:
					return DomainName.Parse("hmac-sha224");
				case TSigAlgorithm.Sha256:
					return DomainName.Parse("hmac-sha256");
				case TSigAlgorithm.Sha256_128:
					return DomainName.Parse("hmac-sha256-128");
				case TSigAlgorithm.Sha384:
					return DomainName.Parse("hmac-sha384");
				case TSigAlgorithm.Sha384_192:
					return DomainName.Parse("hmac-sha384-192");
				case TSigAlgorithm.Sha512:
					return DomainName.Parse("hmac-sha512");
				case TSigAlgorithm.Sha512_256:
					return DomainName.Parse("hmac-sha512-256");

				default:
					return DomainName.Parse("unknown");
			}
		}

		public static TSigAlgorithm GetAlgorithmByName(DomainName name)
		{
			switch (name.ToString().ToLower())
			{
				case "hmac-md5.sig-alg.reg.int.":
					return TSigAlgorithm.Md5;
				case "hmac-sha1.":
					return TSigAlgorithm.Sha1;
				case "hmac-sha224.":
					return TSigAlgorithm.Sha224;
				case "hmac-sha256.":
					return TSigAlgorithm.Sha256;
				case "hmac-sha256-128.":
					return TSigAlgorithm.Sha256_128;
				case "hmac-sha384.":
					return TSigAlgorithm.Sha384;
				case "hmac-sha384-192.":
					return TSigAlgorithm.Sha384_192;
				case "hmac-sha512.":
					return TSigAlgorithm.Sha512;
				case "hmac-sha512-256.":
					return TSigAlgorithm.Sha512_256;

				default:
					return TSigAlgorithm.Unknown;
			}
		}

		public static HMac? GetHashAlgorithm(TSigAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case TSigAlgorithm.Md5:
					return new HMac(new MD5Digest());
				case TSigAlgorithm.Sha1:
					return new HMac(new Sha1Digest());
				case TSigAlgorithm.Sha224:
					return new HMac(new Sha224Digest());
				case TSigAlgorithm.Sha256:
				case TSigAlgorithm.Sha256_128:
					return new HMac(new Sha256Digest());
				case TSigAlgorithm.Sha384:
				case TSigAlgorithm.Sha384_192:
					return new HMac(new Sha256Digest());
				case TSigAlgorithm.Sha512:
				case TSigAlgorithm.Sha512_256:
					return new HMac(new Sha512Digest());

				default:
					return null;
			}
		}

		internal static int GetMaxHashSize(TSigAlgorithm algorithm)
		{
			return GetHashAlgorithm(algorithm)?.GetMacSize() ?? 0;
		}

		internal static bool IsTruncationAllowed(TSigAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case TSigAlgorithm.Sha256_128:
				case TSigAlgorithm.Sha384_192:
				case TSigAlgorithm.Sha512_256:
					return true;

				default:
					return false;
			}
		}
	}
}