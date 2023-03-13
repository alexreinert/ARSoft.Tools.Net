#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
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
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
		///     <a href="https://www.rfc-editor.org/rfc/rfc3658.html">RFC 3658</a>.
		///   </para>
		/// </summary>
		Sha1 = 1,

		/// <summary>
		///   <para>SHA-256</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4509.html">RFC 4509</a>.
		///   </para>
		/// </summary>
		Sha256 = 2,

		/// <summary>
		///   <para>GOST R 34.11-94</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5933.html">RFC 5933</a>.
		///   </para>
		/// </summary>
		EccGost = 3,

		/// <summary>
		///   <para>SHA-384</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6605.html">RFC 6605</a>.
		///   </para>
		/// </summary>
		Sha384 = 4,
	}

	internal static class DnsSecDigestTypeHelper
	{
		public static bool IsSupported(this DnsSecDigestType digest)
		{
			switch (digest)
			{
				case DnsSecDigestType.Sha1:
				case DnsSecDigestType.Sha256:
				case DnsSecDigestType.EccGost:
				case DnsSecDigestType.Sha384:
					return true;

				default:
					return false;
			}
		}
	}
}