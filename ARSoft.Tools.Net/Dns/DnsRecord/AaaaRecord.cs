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

using System.Net;

namespace ARSoft.Tools.Net.Dns
{
    /// <summary>
    ///   <para>IPv6 address</para>
    ///   <para>
    ///     Defined in
    ///     <see cref="!:http://tools.ietf.org/html/rfc3596">RFC 3596</see>
    ///   </para>
    /// </summary>
    public class AaaaRecord : AddressRecordBase
	{
		internal AaaaRecord() {}

		/// <summary>
		///   Creates a new instance of the AaaaRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="address"> IP address of the host </param>
		public AaaaRecord(DomainName name, int timeToLive, IPAddress address)
			: base(name, RecordType.Aaaa, timeToLive, address ?? IPAddress.IPv6None) {}

		protected internal override int MaximumRecordDataLength => 16;
	}
}