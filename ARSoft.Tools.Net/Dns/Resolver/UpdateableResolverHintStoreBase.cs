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
using System.Linq;
using System.Net;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Base class for a ResolverHintStore, which has an updateable local storage for the hints
	/// </summary>
	public abstract class UpdateableResolverHintStoreBase : IResolverHintStore
	{
		private bool _isInitiated;
		private List<IPAddress> _rootServers;
		private List<DsRecord> _rootKeys;

		/// <summary>
		///   List of hints to the root servers
		/// </summary>
		public List<IPAddress> RootServers
		{
			get
			{
				EnsureInit();
				return _rootServers;
			}
			private set { _rootServers = value; }
		}

		/// <summary>
		///   List of DsRecords of the root zone
		/// </summary>
		public List<DsRecord> RootKeys
		{
			get
			{
				EnsureInit();
				return _rootKeys;
			}
			private set { _rootKeys = value; }
		}

		/// <summary>
		///   Forces to update all hints using the given resolver
		/// </summary>
		/// <param name="resolver">The resolver to use for resolving the new hints</param>
		public void Update(IDnsResolver resolver)
		{
			Zone zone = new Zone(DomainName.Root);

			var nameServer = resolver.Resolve<NsRecord>(DomainName.Root, RecordType.Ns);
			zone.AddRange(nameServer);

			foreach (var nsRecord in nameServer)
			{
				zone.AddRange(resolver.Resolve<ARecord>(nsRecord.NameServer, RecordType.A));
				zone.AddRange(resolver.Resolve<AaaaRecord>(nsRecord.NameServer, RecordType.Aaaa));
			}

			zone.AddRange(resolver.Resolve<DnsKeyRecord>(DomainName.Root, RecordType.DnsKey).Where(x => x.IsSecureEntryPoint));

			LoadZoneInternal(zone);

			Save(zone);
		}

		private void EnsureInit()
		{
			if (!_isInitiated)
			{
				Zone zone = Load();

				LoadZoneInternal(zone);

				_isInitiated = true;
			}
		}

		private void LoadZoneInternal(Zone zone)
		{
			var nameServers = zone.OfType<NsRecord>().Where(x => x.Name == DomainName.Root).Select(x => x.NameServer);
			RootServers = zone.Where(x => x.RecordType == RecordType.A || x.RecordType == RecordType.Aaaa).Join(nameServers, x => x.Name, x => x, (x, y) => ((IAddressRecord) x).Address).ToList();
			RootKeys = zone.OfType<DnsKeyRecord>().Where(x => (x.Name == DomainName.Root) && x.IsSecureEntryPoint).Select(x => new DsRecord(x, x.TimeToLive, DnsSecDigestType.Sha256)).ToList();
		}

		/// <summary>
		///   Saves the hints to a local storage
		/// </summary>
		/// <param name="zone"></param>
		protected abstract void Save(Zone zone);

		/// <summary>
		///   Loads the hints from a local storage
		/// </summary>
		/// <returns></returns>
		protected abstract Zone Load();
	}
}