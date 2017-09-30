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
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Delegation signer</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc3658">RFC 3658</see>
	///   </para>
	/// </summary>
	public class DsRecord : DnsRecordBase
	{
		/// <summary>
		///   Key tag
		/// </summary>
		public ushort KeyTag { get; private set; }

		/// <summary>
		///   Algorithm used
		/// </summary>
		public DnsSecAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Type of the digest
		/// </summary>
		public DnsSecDigestType DigestType { get; private set; }

		/// <summary>
		///   Binary data of the digest
		/// </summary>
		public byte[] Digest { get; private set; }

		internal DsRecord() {}

		/// <summary>
		///   Creates a new instance of the DsRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="keyTag"> Key tag </param>
		/// <param name="algorithm"> Algorithm used </param>
		/// <param name="digestType"> Type of the digest </param>
		/// <param name="digest"> Binary data of the digest </param>
		public DsRecord(DomainName name, RecordClass recordClass, int timeToLive, ushort keyTag, DnsSecAlgorithm algorithm, DnsSecDigestType digestType, byte[] digest)
			: base(name, RecordType.Ds, recordClass, timeToLive)
		{
			KeyTag = keyTag;
			Algorithm = algorithm;
			DigestType = digestType;
			Digest = digest ?? new byte[] { };
		}

		/// <summary>
		///   Creates a new instance of the DsRecord class
		/// </summary>
		/// <param name="key"> The key, that should be covered </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="digestType"> Type of the digest </param>
		public DsRecord(DnsKeyRecord key, int timeToLive, DnsSecDigestType digestType)
			: base(key.Name, RecordType.Ds, key.RecordClass, timeToLive)
		{
			KeyTag = key.CalculateKeyTag();
			Algorithm = key.Algorithm;
			DigestType = digestType;
			Digest = CalculateKeyHash(key);
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			KeyTag = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			DigestType = (DnsSecDigestType) resultData[startPosition++];
			Digest = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 4);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length < 4)
				throw new FormatException();

			KeyTag = UInt16.Parse(stringRepresentation[0]);
			Algorithm = (DnsSecAlgorithm) Byte.Parse(stringRepresentation[1]);
			DigestType = (DnsSecDigestType) Byte.Parse(stringRepresentation[2]);
			Digest = String.Join(String.Empty, stringRepresentation.Skip(3)).FromBase16String();
		}

		internal override string RecordDataToString()
		{
			return KeyTag
			       + " " + (byte) Algorithm
			       + " " + (byte) DigestType
			       + " " + Digest.ToBase16String();
		}

		protected internal override int MaximumRecordDataLength => 4 + Digest.Length;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, KeyTag);
			messageData[currentPosition++] = (byte) Algorithm;
			messageData[currentPosition++] = (byte) DigestType;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Digest);
		}

		internal bool IsCovering(DnsKeyRecord dnsKeyRecord)
		{
			if (dnsKeyRecord.Algorithm != Algorithm)
				return false;

			if (dnsKeyRecord.CalculateKeyTag() != KeyTag)
				return false;

			byte[] hash = CalculateKeyHash(dnsKeyRecord);

			return StructuralComparisons.StructuralEqualityComparer.Equals(hash, Digest);
		}

		private byte[] CalculateKeyHash(DnsKeyRecord dnsKeyRecord)
		{
			byte[] buffer = new byte[dnsKeyRecord.Name.MaximumRecordDataLength + 2 + dnsKeyRecord.MaximumRecordDataLength];

			int currentPosition = 0;

			DnsMessageBase.EncodeDomainName(buffer, 0, ref currentPosition, dnsKeyRecord.Name, null, true);
			dnsKeyRecord.EncodeRecordData(buffer, 0, ref currentPosition, null, true);

			var hashAlgorithm = GetHashAlgorithm();

			hashAlgorithm.BlockUpdate(buffer, 0, currentPosition);

			byte[] hash = new byte[hashAlgorithm.GetDigestSize()];

			hashAlgorithm.DoFinal(hash, 0);
			return hash;
		}

		private IDigest GetHashAlgorithm()
		{
			switch (DigestType)
			{
				case DnsSecDigestType.Sha1:
					return new Sha1Digest();

				case DnsSecDigestType.Sha256:
					return new Sha256Digest();

				case DnsSecDigestType.EccGost:
					return new Gost3411Digest();

				case DnsSecDigestType.Sha384:
					return new Sha384Digest();

				default:
					throw new NotSupportedException();
			}
		}
	}
}