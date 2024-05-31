#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;
using Org.BouncyCastle.Crypto.Digests;

namespace ARSoft.Tools.Net
{
	/// <summary>
	///   Extension class for the <see cref="X509Certificate2" /> class
	/// </summary>
	public static class X509Certificate2Extensions
	{
		/// <summary>
		///   Verifies a S/MIME certificate using SMIMEA DNS records.
		/// </summary>
		/// <param name="certificate">The certificate to be verified.</param>
		/// <param name="mailAddress">
		///   The mail address which should be verified. If null is specified, the mail address of the
		///   certificate will be used.
		/// </param>
		/// <param name="chain">The certificate chain which should be used for verification.</param>
		/// <param name="resolver">
		///   The DNSSec resolver which should be used to resolve the SMIMEA dns records. If null is
		///   specified, a self validating stub resolver will be used.
		/// </param>
		/// <returns>true, of the certificate can be verified by SMIMEA dns records; otherwise, false</returns>
		public static bool VerifyCertificateBySMimeA(this X509Certificate2 certificate, string? mailAddress = null, X509Chain? chain = null, IDnsSecResolver? resolver = null)
		{
			mailAddress ??= certificate.GetNameInfo(X509NameType.EmailName, false);

			if (string.IsNullOrWhiteSpace(mailAddress))
				throw new ArgumentException("No valid mail address");

			DomainName smimeaName = GetSMimeAName(mailAddress);

			resolver ??= new SelfValidatingInternalDnsSecStubResolver();

			var dnsResult = resolver.ResolveSecure<SMimeARecord>(smimeaName, RecordType.SMimeA);

			if (dnsResult.ValidationResult != DnsSecValidationResult.Signed)
				return false;

			foreach (var record in dnsResult.Records)
			{
				if (VerifyCertificateBySMimeA(record, certificate, chain))
				{
					return true;
				}
			}

			return false;
		}

		private static DomainName GetSMimeAName(string mail)
		{
			var parts = mail.Split('@');

			if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
				throw new ArgumentException("No valid mail address");

			var hashAlgorithm = new Sha256Digest();

			hashAlgorithm.BlockUpdate(Encoding.UTF8.GetBytes(mail), 0, mail.Length);

			byte[] hash = new byte[hashAlgorithm.GetDigestSize()];

			hashAlgorithm.DoFinal(hash, 0);

			return new DomainName(hash.ToBase16String(0, 28), new DomainName("_smimecert", DomainName.Parse(parts[1])));
		}

		private static bool VerifyCertificateBySMimeA(SMimeARecord smimeaRecord, X509Certificate2 certificate, X509Chain? chain)
		{
			switch (smimeaRecord.CertificateUsage)
			{
				case SMimeARecord.SMimeACertificateUsage.PkixTA:
					return chain != null && chain.ChainElements.Any(x => VerifyCertificateBySMimeA(smimeaRecord, x.Certificate)) && certificate.Verify();

				case SMimeARecord.SMimeACertificateUsage.PkixEE:
					return VerifyCertificateBySMimeA(smimeaRecord, certificate) && certificate.Verify();

				case SMimeARecord.SMimeACertificateUsage.DaneTA:
					return chain != null && chain.ChainElements.Any(x => VerifyCertificateBySMimeA(smimeaRecord, x.Certificate));

				case SMimeARecord.SMimeACertificateUsage.DaneEE:
					return VerifyCertificateBySMimeA(smimeaRecord, certificate);

				default:
					throw new NotSupportedException();
			}
		}

		private static bool VerifyCertificateBySMimeA(SMimeARecord smimeaRecord, X509Certificate2 certificate)
		{
			return SMimeARecord.GetCertificateAssocicationData(smimeaRecord.Selector, smimeaRecord.MatchingType, certificate).SequenceEqual(smimeaRecord.CertificateAssociationData);
		}
	}
}