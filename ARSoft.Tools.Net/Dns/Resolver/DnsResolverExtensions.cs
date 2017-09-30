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
using System.Threading;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Extension methods for DNS resolvers
	/// </summary>
	public static class DnsResolverExtensions
	{
		/// <summary>
		///   Queries a dns resolver for IP addresses of a host.
		/// </summary>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="name"> Host name, that should be queried </param>
		/// <returns> A list of matching host addresses </returns>
		public static List<IPAddress> ResolveHost(this IDnsResolver resolver, DomainName name)
		{
			List<IPAddress> result = new List<IPAddress>();

			List<AaaaRecord> aaaaRecords = resolver.Resolve<AaaaRecord>(name, RecordType.Aaaa);
			if (aaaaRecords != null)
				result.AddRange(aaaaRecords.Select(x => x.Address));

			List<ARecord> aRecords = resolver.Resolve<ARecord>(name);
			if (aRecords != null)
				result.AddRange(aRecords.Select(x => x.Address));

			return result;
		}

		/// <summary>
		///   Queries a dns resolver for IP addresses of a host.
		/// </summary>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="name"> Host name, that should be queried </param>
		/// <returns> A list of matching host addresses </returns>
		public static List<IPAddress> ResolveHost(this IDnsResolver resolver, string name)
		{
			return resolver.ResolveHost(DomainName.Parse(name));
		}

		/// <summary>
		///   Queries a dns resolver for IP addresses of a host as an asynchronous operation.
		/// </summary>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="name"> Host name, that should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> A list of matching host addresses </returns>
		public static async Task<List<IPAddress>> ResolveHostAsync(this IDnsResolver resolver, DomainName name, CancellationToken token = default(CancellationToken))
		{
			List<IPAddress> result = new List<IPAddress>();

			List<AaaaRecord> aaaaRecords = await resolver.ResolveAsync<AaaaRecord>(name, RecordType.Aaaa, token: token);
			if (aaaaRecords != null)
				result.AddRange(aaaaRecords.Select(x => x.Address));

			List<ARecord> aRecords = await resolver.ResolveAsync<ARecord>(name, token: token);
			if (aRecords != null)
				result.AddRange(aRecords.Select(x => x.Address));

			return result;
		}

		/// <summary>
		///   Queries a dns resolver for IP addresses of a host as an asynchronous operation.
		/// </summary>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="name"> Host name, that should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> A list of matching host addresses </returns>
		public static Task<List<IPAddress>> ResolveHostAsync(this IDnsResolver resolver, string name, CancellationToken token = default(CancellationToken))
		{
			return resolver.ResolveHostAsync(DomainName.Parse(name), token);
		}

		/// <summary>
		///   Queries a dns resolver for reverse name of an IP address.
		/// </summary>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="address"> The address, that should be queried </param>
		/// <returns> The reverse name of the IP address </returns>
		public static DomainName ResolvePtr(this IDnsResolver resolver, IPAddress address)
		{
			List<PtrRecord> ptrRecords = resolver.Resolve<PtrRecord>(address.GetReverseLookupDomain(), RecordType.Ptr);
			return ptrRecords.Select(x => x.PointerDomainName).FirstOrDefault();
		}

		/// <summary>
		///   Queries a dns resolver for reverse name of an IP address as an asynchronous operation.
		/// </summary>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="address"> The address, that should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> The reverse name of the IP address </returns>
		public static async Task<DomainName> ResolvePtrAsync(this IDnsResolver resolver, IPAddress address, CancellationToken token = default(CancellationToken))
		{
			List<PtrRecord> ptrRecords = await resolver.ResolveAsync<PtrRecord>(address.GetReverseLookupDomain(), RecordType.Ptr, token: token);
			return ptrRecords.Select(x => x.PointerDomainName).FirstOrDefault();
		}

		/// <summary>
		///   Queries a dns resolver for specified records.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public static List<T> Resolve<T>(this IDnsResolver resolver, string name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
		{
			return resolver.Resolve<T>(DomainName.Parse(name), recordType, recordClass);
		}

		/// <summary>
		///   Queries a dns resolver for specified records as an asynchronous operation.
		/// </summary>
		/// <typeparam name="T"> Type of records, that should be returned </typeparam>
		/// <param name="resolver"> The resolver instance, that should be used for queries </param>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns> A list of matching <see cref="DnsRecordBase">records</see> </returns>
		public static Task<List<T>> ResolveAsync<T>(this IDnsResolver resolver, string name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default(CancellationToken))
			where T : DnsRecordBase
		{
			return resolver.ResolveAsync<T>(DomainName.Parse(name), recordType, recordClass, token);
		}
	}
}