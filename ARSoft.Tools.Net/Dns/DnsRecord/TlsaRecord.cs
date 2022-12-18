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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>TLSA</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
	///   </para>
	/// </summary>
	public class TlsaRecord : DnsRecordBase
	{
		/// <summary>
		///   Certificate Usage
		/// </summary>
		public enum TlsaCertificateUsage : byte
		{
			/// <summary>
			///   <para>CA constraint</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			// ReSharper disable once InconsistentNaming
			PkixTA = 0,

			/// <summary>
			///   <para>Service certificate constraint</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			// ReSharper disable once InconsistentNaming
			PkixEE = 1,

			/// <summary>
			///   <para> Trust anchor assertion</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			// ReSharper disable once InconsistentNaming
			DaneTA = 2,

			/// <summary>
			///   <para>
			///     Domain-issued certificate
			///   </para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			// ReSharper disable once InconsistentNaming
			DaneEE = 3,

			/// <summary>
			///   <para>
			///     Reserved for Private Use
			///   </para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			PrivCert = 255,
		}

		/// <summary>
		///   Selector
		/// </summary>
		public enum TlsaSelector : byte
		{
			/// <summary>
			///   <para>Full certificate</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			FullCertificate = 0,

			/// <summary>
			///   <para>DER-encoded binary structure</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			SubjectPublicKeyInfo = 1,
		}

		/// <summary>
		///   Matching Type
		/// </summary>
		public enum TlsaMatchingType : byte
		{
			/// <summary>
			///   <para>No hash used</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			Full = 0,

			/// <summary>
			///   <para>SHA-256 hash</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			Sha256Hash = 1,

			/// <summary>
			///   <para>SHA-512 hash</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			Sha512Hash = 2,

			/// <summary>
			///   <para>Reserved for Private Use</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc6698.html">RFC 6698</a>.
			///   </para>
			/// </summary>
			PrivMatch = 255,
		}

		/// <summary>
		///   The certificate usage
		/// </summary>
		public TlsaCertificateUsage CertificateUsage { get; private set; }

		/// <summary>
		///   The selector
		/// </summary>
		public TlsaSelector Selector { get; private set; }

		/// <summary>
		///   The matching type
		/// </summary>
		public TlsaMatchingType MatchingType { get; private set; }

		/// <summary>
		///   The certificate association data
		/// </summary>
		public byte[] CertificateAssociationData { get; private set; }

		internal TlsaRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			CertificateUsage = (TlsaCertificateUsage) resultData[currentPosition++];
			Selector = (TlsaSelector) resultData[currentPosition++];
			MatchingType = (TlsaMatchingType) resultData[currentPosition++];
			CertificateAssociationData = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length - 3);
		}

		internal TlsaRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length < 4)
				throw new FormatException();

			CertificateUsage = (TlsaCertificateUsage) Byte.Parse(stringRepresentation[0]);
			Selector = (TlsaSelector) Byte.Parse(stringRepresentation[1]);
			MatchingType = (TlsaMatchingType) Byte.Parse(stringRepresentation[2]);
			CertificateAssociationData = String.Join(String.Empty, stringRepresentation.Skip(3)).FromBase16String();
		}

		/// <summary>
		///   Creates a new instance of the TlsaRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="certificateUsage">The certificate usage</param>
		/// <param name="selector">The selector</param>
		/// <param name="matchingType">The matching type</param>
		/// <param name="certificateAssociationData">The certificate association data</param>
		public TlsaRecord(DomainName name, int timeToLive, TlsaCertificateUsage certificateUsage, TlsaSelector selector, TlsaMatchingType matchingType, byte[] certificateAssociationData)
			: base(name, RecordType.Tlsa, RecordClass.INet, timeToLive)
		{
			CertificateUsage = certificateUsage;
			Selector = selector;
			MatchingType = matchingType;
			CertificateAssociationData = certificateAssociationData ?? new byte[] { };
		}

		/// <summary>
		///   Creates a new instance of the TlsaRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="certificateUsage">The certificate usage</param>
		/// <param name="selector">The selector</param>
		/// <param name="matchingType">The matching type</param>
		/// <param name="certificate">The certificate to get the association data from</param>
		public TlsaRecord(DomainName name, int timeToLive, TlsaCertificateUsage certificateUsage, TlsaSelector selector, TlsaMatchingType matchingType, X509Certificate certificate)
			: base(name, RecordType.Tlsa, RecordClass.INet, timeToLive)
		{
			CertificateUsage = certificateUsage;
			Selector = selector;
			MatchingType = matchingType;
			CertificateAssociationData = GetCertificateAssocicationData(selector, matchingType, certificate);
		}

		internal static byte[] GetCertificateAssocicationData(TlsaSelector selector, TlsaMatchingType matchingType, X509Certificate certificate)
		{
			byte[] selectedBytes;
			switch (selector)
			{
				case TlsaSelector.FullCertificate:
					selectedBytes = certificate.GetRawCertData();
					break;

				case TlsaSelector.SubjectPublicKeyInfo:
					selectedBytes = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(DotNetUtilities.FromX509Certificate(certificate).GetPublicKey()).GetDerEncoded();
					break;

				default:
					throw new NotSupportedException();
			}

			byte[] matchingBytes;
			switch (matchingType)
			{
				case TlsaMatchingType.Full:
					matchingBytes = selectedBytes;
					break;

				case TlsaMatchingType.Sha256Hash:
					Sha256Digest sha256Digest = new Sha256Digest();
					sha256Digest.BlockUpdate(selectedBytes, 0, selectedBytes.Length);
					matchingBytes = new byte[sha256Digest.GetDigestSize()];
					sha256Digest.DoFinal(matchingBytes, 0);
					break;

				case TlsaMatchingType.Sha512Hash:
					Sha512Digest sha512Digest = new Sha512Digest();
					sha512Digest.BlockUpdate(selectedBytes, 0, selectedBytes.Length);
					matchingBytes = new byte[sha512Digest.GetDigestSize()];
					sha512Digest.DoFinal(matchingBytes, 0);
					break;

				default:
					throw new NotSupportedException();
			}

			return matchingBytes;
		}

		internal override string RecordDataToString()
		{
			return (byte) CertificateUsage
			       + " " + (byte) Selector
			       + " " + (byte) MatchingType
			       + " " + String.Join(String.Empty, CertificateAssociationData.ToBase16String());
		}

		protected internal override int MaximumRecordDataLength => 3 + CertificateAssociationData.Length;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			messageData[currentPosition++] = (byte) CertificateUsage;
			messageData[currentPosition++] = (byte) Selector;
			messageData[currentPosition++] = (byte) MatchingType;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, CertificateAssociationData);
		}
	}
}