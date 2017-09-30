#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
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
using System.Net;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Implementation of IResolverHintStore, which uses statically linked hints
	/// </summary>
	public class StaticResolverHintStore : IResolverHintStore
	{
		private static readonly List<IPAddress> _rootServers = new List<IPAddress>()
		{
			// a.root-servers.net
			IPAddress.Parse("198.41.0.4"),
			IPAddress.Parse("2001:503:ba3e::2:30"),

			// b.root-servers.net
			IPAddress.Parse("192.228.79.201"),
			IPAddress.Parse("2001:500:84::b"),

			// c.root-servers.net
			IPAddress.Parse("192.33.4.12"),
			IPAddress.Parse("2001:500:2::c"),

			// d.root-servers.net
			IPAddress.Parse("199.7.91.13"),
			IPAddress.Parse("2001:500:2d::d"),

			// e.root-servers.net
			IPAddress.Parse("192.203.230.10"),

			// f.root-servers.net
			IPAddress.Parse("192.5.5.241"),
			IPAddress.Parse("2001:500:2f::f"),

			// g.root-servers.net
			IPAddress.Parse("192.112.36.4"),

			// h.root-servers.net
			IPAddress.Parse("128.63.2.53"),
			IPAddress.Parse("2001:500:1::803f:235"),

			// i.root-servers.net
			IPAddress.Parse("192.36.148.17"),
			IPAddress.Parse("2001:7fe::53"),

			// j.root-servers.net
			IPAddress.Parse("192.58.128.30"),
			IPAddress.Parse("2001:503:c27::2:30"),

			// k.root-servers.net
			IPAddress.Parse("193.0.14.129"),
			IPAddress.Parse("2001:7fd::1"),

			// l.root-servers.net
			IPAddress.Parse("199.7.83.42"),
			IPAddress.Parse("2001:500:3::42"),

			// m.root-servers.net
			IPAddress.Parse("202.12.27.33"),
			IPAddress.Parse("2001:dc3::35")
		};

		/// <summary>
		///   List of hints to the root servers
		/// </summary>
		public List<IPAddress> RootServers => _rootServers;

		private static readonly List<DsRecord> _rootKeys = new List<DsRecord>()
		{
			new DsRecord(DomainName.Root, RecordClass.INet, 0, 19036, DnsSecAlgorithm.RsaSha256, DnsSecDigestType.Sha256, "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5".FromBase16String())
		};

		/// <summary>
		///   List of DsRecords of the root zone
		/// </summary>
		public List<DsRecord> RootKeys => _rootKeys;
	}
}