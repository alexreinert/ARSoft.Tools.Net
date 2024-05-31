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

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using static ARSoft.Tools.Net.Dns.SMimeARecord;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>SMIMEA</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc8162.html">RFC 8162</a>.
///   </para>
/// </summary>
public class SMimeARecord : DnsRecordBase
{
	/// <summary>
	///   Certificate Usage
	/// </summary>
	public enum SMimeACertificateUsage : byte
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
	public enum SMimeASelector : byte
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
	public enum SMimeAMatchingType : byte
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
	public SMimeACertificateUsage CertificateUsage { get; private set; }

	/// <summary>
	///   The selector
	/// </summary>
	public SMimeASelector Selector { get; private set; }

	/// <summary>
	///   The matching type
	/// </summary>
	public SMimeAMatchingType MatchingType { get; private set; }

	/// <summary>
	///   The certificate association data
	/// </summary>
	public byte[] CertificateAssociationData { get; private set; }

	internal SMimeARecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
		: base(name, recordType, recordClass, timeToLive)
	{
		CertificateUsage = (SMimeACertificateUsage) resultData[currentPosition++];
		Selector = (SMimeASelector) resultData[currentPosition++];
		MatchingType = (SMimeAMatchingType) resultData[currentPosition++];
		CertificateAssociationData = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length - 3);
	}

	internal SMimeARecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
		: base(name, recordType, recordClass, timeToLive)
	{
		if (stringRepresentation.Length < 4)
			throw new FormatException();

		CertificateUsage = (SMimeACertificateUsage) Byte.Parse(stringRepresentation[0]);
		Selector = (SMimeASelector) Byte.Parse(stringRepresentation[1]);
		MatchingType = (SMimeAMatchingType) Byte.Parse(stringRepresentation[2]);
		CertificateAssociationData = String.Join(String.Empty, stringRepresentation.Skip(3)).FromBase16String();
	}

	/// <summary>
	///   Creates a new instance of the SMimeARecord class
	/// </summary>
	/// <param name="name"> Domain name of the host </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="certificateUsage">The certificate usage</param>
	/// <param name="selector">The selector</param>
	/// <param name="matchingType">The matching type</param>
	/// <param name="certificateAssociationData">The certificate association data</param>
	public SMimeARecord(DomainName name, int timeToLive, SMimeACertificateUsage certificateUsage, SMimeASelector selector, SMimeAMatchingType matchingType, byte[] certificateAssociationData)
		: base(name, RecordType.SMimeA, RecordClass.INet, timeToLive)
	{
		CertificateUsage = certificateUsage;
		Selector = selector;
		MatchingType = matchingType;
		CertificateAssociationData = certificateAssociationData;
	}

	/// <summary>
	///   Creates a new instance of the SMimeARecord class
	/// </summary>
	/// <param name="name"> Domain name of the host </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="certificateUsage">The certificate usage</param>
	/// <param name="selector">The selector</param>
	/// <param name="matchingType">The matching type</param>
	/// <param name="certificate">The certificate to get the association data from</param>
	public SMimeARecord(DomainName name, int timeToLive, SMimeACertificateUsage certificateUsage, SMimeASelector selector, SMimeAMatchingType matchingType, X509Certificate certificate)
		: base(name, RecordType.SMimeA, RecordClass.INet, timeToLive)
	{
		CertificateUsage = certificateUsage;
		Selector = selector;
		MatchingType = matchingType;
		CertificateAssociationData = GetCertificateAssocicationData(selector, matchingType, certificate);
	}

	internal static byte[] GetCertificateAssocicationData(SMimeASelector selector, SMimeAMatchingType matchingType, X509Certificate certificate)
	{
		byte[] selectedBytes;
		switch (selector)
		{
			case SMimeASelector.FullCertificate:
				selectedBytes = certificate.GetRawCertData();
				break;

			case SMimeASelector.SubjectPublicKeyInfo:
				selectedBytes = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(DotNetUtilities.FromX509Certificate(certificate).GetPublicKey()).GetDerEncoded();
				break;

			default:
				throw new NotSupportedException();
		}

		byte[] matchingBytes;
		switch (matchingType)
		{
			case SMimeAMatchingType.Full:
				matchingBytes = selectedBytes;
				break;

			case SMimeAMatchingType.Sha256Hash:
				Sha256Digest sha256Digest = new Sha256Digest();
				sha256Digest.BlockUpdate(selectedBytes, 0, selectedBytes.Length);
				matchingBytes = new byte[sha256Digest.GetDigestSize()];
				sha256Digest.DoFinal(matchingBytes, 0);
				break;

			case SMimeAMatchingType.Sha512Hash:
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