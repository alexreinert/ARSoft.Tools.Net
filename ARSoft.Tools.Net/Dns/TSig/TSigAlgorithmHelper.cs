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

using System.Security.Cryptography;

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
				case TSigAlgorithm.Sha256:
					return DomainName.Parse("hmac-sha256");
				case TSigAlgorithm.Sha384:
					return DomainName.Parse("hmac-sha384");
				case TSigAlgorithm.Sha512:
					return DomainName.Parse("hmac-sha512");

				default:
					return null;
			}
		}

		public static TSigAlgorithm GetAlgorithmByName(DomainName name)
		{
			switch (name.ToString().ToLower())
			{
				case "hmac-md5.sig-alg.reg.int":
					return TSigAlgorithm.Md5;
				case "hmac-sha1":
					return TSigAlgorithm.Sha1;
				case "hmac-sha256":
					return TSigAlgorithm.Sha256;
				case "hmac-sha384":
					return TSigAlgorithm.Sha384;
				case "hmac-sha512":
					return TSigAlgorithm.Sha512;

				default:
					return TSigAlgorithm.Unknown;
			}
		}

		public static KeyedHashAlgorithm GetHashAlgorithm(TSigAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case TSigAlgorithm.Md5:
					return new HMACMD5();
				case TSigAlgorithm.Sha1:
					return new HMACSHA1();
				case TSigAlgorithm.Sha256:
					return new HMACSHA256();
				case TSigAlgorithm.Sha384:
					return new HMACSHA384();
				case TSigAlgorithm.Sha512:
					return new HMACSHA512();

				default:
					return null;
			}
		}

		internal static int GetHashSize(TSigAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case TSigAlgorithm.Md5:
					return 16;
				case TSigAlgorithm.Sha1:
					return 20;
				case TSigAlgorithm.Sha256:
					return 32;
				case TSigAlgorithm.Sha384:
					return 48;
				case TSigAlgorithm.Sha512:
					return 64;

				default:
					return 0;
			}
		}
	}
}