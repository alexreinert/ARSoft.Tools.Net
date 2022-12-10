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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   DNSSEC algorithm type
	/// </summary>
	public enum DnsSecAlgorithm : byte
	{
		/// <summary>
		///   <para>RSA MD5</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3110.html">RFC 3110</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		[Obsolete] RsaMd5 = 1,

		/// <summary>
		///   <para>Diffie Hellman</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2539.html">RFC 2539</a>.
		///   </para>
		/// </summary>
		[Obsolete] DiffieHellman = 2,

		/// <summary>
		///   <para>DSA/SHA-1</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		[Obsolete] Dsa = 3,

		/// <summary>
		///   <para>RSA/SHA-1</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc3110.html">RFC 3110</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		RsaSha1 = 5,

		/// <summary>
		///   <para>DSA/SHA-1 using NSEC3 hashs</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>.
		///   </para>
		/// </summary>
		[Obsolete] DsaNsec3Sha1 = 6,

		/// <summary>
		///   <para>RSA/SHA-1 using NSEC3 hashs</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>.
		///   </para>
		/// </summary>
		RsaSha1Nsec3Sha1 = 7,

		/// <summary>
		///   <para>RSA/SHA-256</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5702.html">RFC 5702</a>.
		///   </para>
		/// </summary>
		RsaSha256 = 8,

		/// <summary>
		///   <para>RSA/SHA-512</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5702.html">RFC 5702</a>.
		///   </para>
		/// </summary>
		RsaSha512 = 10,

		/// <summary>
		///   <para>GOST R 34.10-2001</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc5933.html">RFC 5933</a>.
		///   </para>
		/// </summary>
		[Obsolete] EccGost = 12,

		/// <summary>
		///   <para>ECDSA Curve P-256 with SHA-256</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6605.html">RFC 6605</a>.
		///   </para>
		/// </summary>
		EcDsaP256Sha256 = 13,

		/// <summary>
		///   <para>ECDSA Curve P-384 with SHA-384</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc6605.html">RFC 6605</a>.
		///   </para>
		/// </summary>
		EcDsaP384Sha384 = 14,

		/// <summary>
		///   <para>EdDSA with Ed25519 curve</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8080.html">RFC 8080</a>.
		///   </para>
		/// </summary>
		Ed25519 = 15,

		/// <summary>
		///   <para>EdDSA with Ed448 curve</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8080.html">RFC 8080</a>.
		///   </para>
		/// </summary>
		Ed448 = 16,

		/// <summary>
		///   <para>Indirect</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		Indirect = 252,

		/// <summary>
		///   <para>Private key using named algorithm</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		PrivateDns = 253,

		/// <summary>
		///   <para>Private key using algorithm object identifier</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		PrivateOid = 254,
	}

	internal static class DnsSecAlgorithmHelper
	{
		public static bool IsSupported(this DnsSecAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case DnsSecAlgorithm.RsaSha1:
				case DnsSecAlgorithm.RsaSha1Nsec3Sha1:
				case DnsSecAlgorithm.RsaSha256:
				case DnsSecAlgorithm.RsaSha512:
#pragma warning disable 0612
				case DnsSecAlgorithm.EccGost:
#pragma warning restore 0612
				case DnsSecAlgorithm.EcDsaP256Sha256:
				case DnsSecAlgorithm.EcDsaP384Sha384:
				case DnsSecAlgorithm.Ed25519:
				case DnsSecAlgorithm.Ed448:
					return true;

				default:
					return false;
			}
		}

		public static bool IsCompatibleWithNSec(this DnsSecAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case DnsSecAlgorithm.RsaSha1:
				case DnsSecAlgorithm.RsaSha256:
				case DnsSecAlgorithm.RsaSha512:
#pragma warning disable 0612
				case DnsSecAlgorithm.EccGost:
#pragma warning restore 0612
				case DnsSecAlgorithm.EcDsaP256Sha256:
				case DnsSecAlgorithm.EcDsaP384Sha384:
				case DnsSecAlgorithm.Ed25519:
				case DnsSecAlgorithm.Ed448:
					return true;

				default:
					return false;
			}
		}

		public static bool IsCompatibleWithNSec3(this DnsSecAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case DnsSecAlgorithm.RsaSha1Nsec3Sha1:
				case DnsSecAlgorithm.RsaSha256:
				case DnsSecAlgorithm.RsaSha512:
#pragma warning disable 0612
				case DnsSecAlgorithm.EccGost:
#pragma warning restore 0612
				case DnsSecAlgorithm.EcDsaP256Sha256:
				case DnsSecAlgorithm.EcDsaP384Sha384:
				case DnsSecAlgorithm.Ed25519:
				case DnsSecAlgorithm.Ed448:
					return true;

				default:
					return false;
			}
		}
	}
}