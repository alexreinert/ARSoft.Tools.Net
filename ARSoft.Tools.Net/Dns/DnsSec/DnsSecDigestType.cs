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


namespace ARSoft.Tools.Net.Dns
{
    /// <summary>
    ///   Type of DNSSEC digest
    /// </summary>
    public enum DnsSecDigestType : byte
	{
		/// <summary>
		///   <para>SHA-1</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3658">RFC 3658</see>
		///   </para>
		/// </summary>
		Sha1 = 1,

		/// <summary>
		///   <para>SHA-256</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4509">RFC 4509</see>
		///   </para>
		/// </summary>
		Sha256 = 2,

		/// <summary>
		///   <para>GOST R 34.11-94</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5933">RFC 5933</see>
		///   </para>
		/// </summary>
		EccGost = 3,

		/// <summary>
		///   <para>SHA-384</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6605">RFC 6605</see>
		///   </para>
		/// </summary>
		Sha384 = 4,
	}
}