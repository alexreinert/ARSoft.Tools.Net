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
using System.Text;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>DNS Key record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
	///   </para>
	/// </summary>
	public class DnsKeyRecord : DnsRecordBase
	{
		private static readonly SecureRandom _secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

		/// <summary>
		///   Flags of the key
		/// </summary>
		public DnsKeyFlags Flags { get; private set; }

		/// <summary>
		///   Protocol field
		/// </summary>
		public byte Protocol { get; private set; }

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public DnsSecAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Binary data of the public key
		/// </summary>
		public byte[] PublicKey { get; private set; }

		/// <summary>
		///   Binary data of the private key
		/// </summary>
		public byte[] PrivateKey { get; }

		/// <summary>
		///   <para>Record holds a DNS zone key</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3757">RFC 3757</see>
		///   </para>
		/// </summary>
		public bool IsZoneKey
		{
			get { return (Flags & DnsKeyFlags.Zone) == DnsKeyFlags.Zone; }
			set
			{
				if (value)
				{
					Flags |= DnsKeyFlags.Zone;
				}
				else
				{
					Flags &= ~DnsKeyFlags.Zone;
				}
			}
		}

		/// <summary>
		///   <para>Key is intended for use as a secure entry point</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3757">RFC 3757</see>
		///   </para>
		/// </summary>
		public bool IsSecureEntryPoint
		{
			get { return (Flags & DnsKeyFlags.SecureEntryPoint) == DnsKeyFlags.SecureEntryPoint; }
			set
			{
				if (value)
				{
					Flags |= DnsKeyFlags.SecureEntryPoint;
				}
				else
				{
					Flags &= ~DnsKeyFlags.SecureEntryPoint;
				}
			}
		}

		/// <summary>
		///   <para>Key is intended for use as a secure entry point</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5011">RFC 5011</see>
		///   </para>
		/// </summary>
		public bool IsRevoked
		{
			get { return (Flags & DnsKeyFlags.Revoke) == DnsKeyFlags.Revoke; }
			set
			{
				if (value)
				{
					Flags |= DnsKeyFlags.Revoke;
				}
				else
				{
					Flags &= ~DnsKeyFlags.Revoke;
				}
			}
		}

		/// <summary>
		///   <para>Calculates the key tag</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///   </para>
		/// </summary>
		/// <returns></returns>
		public ushort CalculateKeyTag()
		{
			if (Algorithm == DnsSecAlgorithm.RsaMd5)
				return (ushort) (PublicKey[PublicKey.Length - 4] & PublicKey[PublicKey.Length - 3] << 8);

			byte[] buffer = new byte[MaximumRecordDataLength];
			int currentPosition = 0;
			EncodeRecordData(buffer, 0, ref currentPosition, null, false);

			ulong ac = 0;

			for (int i = 0; i < currentPosition; ++i)
			{
				ac += ((i & 1) == 1) ? buffer[i] : (ulong) buffer[i] << 8;
			}

			ac += (ac >> 16) & 0xFFFF;

			ushort res = (ushort) (ac & 0xffff);

			return res;
		}

		internal DnsKeyRecord() {}

		/// <summary>
		///   Creates a new instance of the DnsKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="flags"> Flags of the key </param>
		/// <param name="protocol"> Protocol field </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="publicKey"> Binary data of the public key </param>
		public DnsKeyRecord(DomainName name, RecordClass recordClass, int timeToLive, DnsKeyFlags flags, byte protocol, DnsSecAlgorithm algorithm, byte[] publicKey)
			: this(name, recordClass, timeToLive, flags, protocol, algorithm, publicKey, null) {}

		/// <summary>
		///   Creates a new instance of the DnsKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="flags"> Flags of the key </param>
		/// <param name="protocol"> Protocol field </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="publicKey"> Binary data of the public key </param>
		/// <param name="privateKey"> Binary data of the private key </param>
		public DnsKeyRecord(DomainName name, RecordClass recordClass, int timeToLive, DnsKeyFlags flags, byte protocol, DnsSecAlgorithm algorithm, byte[] publicKey, byte[] privateKey)
			: base(name, RecordType.DnsKey, recordClass, timeToLive)
		{
			Flags = flags;
			Protocol = protocol;
			Algorithm = algorithm;
			PublicKey = publicKey;
			PrivateKey = privateKey;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Flags = (DnsKeyFlags) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Protocol = resultData[startPosition++];
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 4);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length < 4)
				throw new FormatException();

			Flags = (DnsKeyFlags) UInt16.Parse(stringRepresentation[0]);
			Protocol = Byte.Parse(stringRepresentation[1]);
			Algorithm = (DnsSecAlgorithm) Byte.Parse(stringRepresentation[2]);
			PublicKey = String.Join(String.Empty, stringRepresentation.Skip(3)).FromBase64String();
		}

		internal override string RecordDataToString()
		{
			return (ushort) Flags
			       + " " + Protocol
			       + " " + (byte) Algorithm
			       + " " + PublicKey.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength => 4 + PublicKey.Length;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Flags);
			messageData[currentPosition++] = Protocol;
			messageData[currentPosition++] = (byte) Algorithm;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}

		internal byte[] Sign(byte[] buffer, int length)
		{
			switch (Algorithm)
			{
				case DnsSecAlgorithm.RsaSha1:
				case DnsSecAlgorithm.RsaSha1Nsec3Sha1:
					return SignRsa(new Sha1Digest(), buffer, length);

				case DnsSecAlgorithm.RsaSha256:
					return SignRsa(new Sha256Digest(), buffer, length);

				case DnsSecAlgorithm.RsaSha512:
					return SignRsa(new Sha512Digest(), buffer, length);

				case DnsSecAlgorithm.Dsa:
				case DnsSecAlgorithm.DsaNsec3Sha1:
					return SignDsa(buffer, length);

				case DnsSecAlgorithm.EccGost:
					return SignGost(buffer, length);

				case DnsSecAlgorithm.EcDsaP256Sha256:
					return SignEcDsa(new Sha256Digest(), buffer, length);

				case DnsSecAlgorithm.EcDsaP384Sha384:
					return SignEcDsa(new Sha384Digest(), buffer, length);

				default:
					throw new NotSupportedException();
			}
		}

		private byte[] SignRsa(IDigest digest, byte[] buffer, int length)
		{
			RsaDigestSigner signer = new RsaDigestSigner(digest);

			signer.Init(true, new ParametersWithRandom(PrivateKeyFactory.CreateKey(PrivateKey), _secureRandom));

			signer.BlockUpdate(buffer, 0, length);
			return signer.GenerateSignature();
		}

		private byte[] SignDsa(byte[] buffer, int length)
		{
			var signer = new DsaSigner();
			signer.Init(true, new ParametersWithRandom(PrivateKeyFactory.CreateKey(PrivateKey), _secureRandom));

			var sha1 = new Sha1Digest();

			sha1.BlockUpdate(buffer, 0, length);
			byte[] hash = new byte[sha1.GetDigestSize()];
			sha1.DoFinal(hash, 0);

			var signature = signer.GenerateSignature(hash);

			byte[] res = new byte[41];

			res[0] = PublicKey[0];

			signature[0].ToByteArrayUnsigned().CopyTo(res, 1);
			signature[1].ToByteArrayUnsigned().CopyTo(res, 21);

			return res;
		}

		private byte[] SignGost(byte[] buffer, int length)
		{
			ECGost3410Signer signer = new ECGost3410Signer();
			signer.Init(true, new ParametersWithRandom(PrivateKeyFactory.CreateKey(PrivateKey), _secureRandom));

			var digest = new Gost3411Digest();

			digest.BlockUpdate(buffer, 0, length);
			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			var signature = signer.GenerateSignature(hash);

			byte[] res = new byte[64];

			signature[0].ToByteArrayUnsigned().CopyTo(res, 32);
			signature[1].ToByteArrayUnsigned().CopyTo(res, 0);

			return res;
		}

		private byte[] SignEcDsa(IDigest digest, byte[] buffer, int length)
		{
			int digestSize = digest.GetDigestSize();

			ECDsaSigner signer = new ECDsaSigner();

			signer.Init(true, new ParametersWithRandom(PrivateKeyFactory.CreateKey(PrivateKey), _secureRandom));

			digest.BlockUpdate(buffer, 0, length);
			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			var signature = signer.GenerateSignature(hash);

			byte[] res = new byte[digestSize * 2];

			signature[0].ToByteArrayUnsigned().CopyTo(res, 0);
			signature[1].ToByteArrayUnsigned().CopyTo(res, digestSize);

			return res;
		}

		internal bool Verify(byte[] buffer, int length, byte[] signature)
		{
			switch (Algorithm)
			{
				case DnsSecAlgorithm.RsaSha1:
				case DnsSecAlgorithm.RsaSha1Nsec3Sha1:
					return VerifyRsa(new Sha1Digest(), buffer, length, signature);

				case DnsSecAlgorithm.RsaSha256:
					return VerifyRsa(new Sha256Digest(), buffer, length, signature);

				case DnsSecAlgorithm.RsaSha512:
					return VerifyRsa(new Sha512Digest(), buffer, length, signature);

				case DnsSecAlgorithm.Dsa:
				case DnsSecAlgorithm.DsaNsec3Sha1:
					return VerifyDsa(buffer, length, signature);

				case DnsSecAlgorithm.EccGost:
					return VerifyGost(buffer, length, signature);

				case DnsSecAlgorithm.EcDsaP256Sha256:
					return VerifyEcDsa(new Sha256Digest(), NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1), buffer, length, signature);

				case DnsSecAlgorithm.EcDsaP384Sha384:
					return VerifyEcDsa(new Sha384Digest(), NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1), buffer, length, signature);

				default:
					throw new NotSupportedException();
			}
		}

		private bool VerifyRsa(IDigest digest, byte[] buffer, int length, byte[] signature)
		{
			RsaDigestSigner signer = new RsaDigestSigner(digest);

			int exponentOffset = 1;
			int exponentLength = PublicKey[0] == 0 ? DnsMessageBase.ParseUShort(PublicKey, ref exponentOffset) : PublicKey[0];
			int moduloOffset = exponentOffset + exponentLength;
			int moduloLength = PublicKey.Length - moduloOffset;

			RsaKeyParameters parameters = new RsaKeyParameters(false, new BigInteger(1, PublicKey, moduloOffset, moduloLength), new BigInteger(1, PublicKey, exponentOffset, exponentLength));

			signer.Init(false, new ParametersWithRandom(parameters, _secureRandom));

			signer.BlockUpdate(buffer, 0, length);
			return signer.VerifySignature(signature);
		}

		private bool VerifyDsa(byte[] buffer, int length, byte[] signature)
		{
			int numberSize = 64 + PublicKey[0] * 8;

			DsaPublicKeyParameters parameters = new DsaPublicKeyParameters(
				new BigInteger(1, PublicKey, 21 + 2 * numberSize, numberSize),
				new DsaParameters(
					new BigInteger(1, PublicKey, 21, numberSize),
					new BigInteger(1, PublicKey, 1, 20),
					new BigInteger(1, PublicKey, 21 + numberSize, numberSize))
				);

			var dsa = new DsaSigner();
			dsa.Init(false, parameters);

			var sha1 = new Sha1Digest();

			sha1.BlockUpdate(buffer, 0, length);
			byte[] hash = new byte[sha1.GetDigestSize()];
			sha1.DoFinal(hash, 0);

			return dsa.VerifySignature(hash, new BigInteger(1, signature, 1, 20), new BigInteger(1, signature, 21, 20));
		}

		private bool VerifyGost(byte[] buffer, int length, byte[] signature)
		{
			ECDomainParameters dParams = ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
			byte[] reversedPublicKey = PublicKey.Reverse().ToArray();
			ECPoint q = dParams.Curve.CreatePoint(new BigInteger(1, reversedPublicKey, 32, 32), new BigInteger(1, reversedPublicKey, 0, 32), false);
			ECPublicKeyParameters parameters = new ECPublicKeyParameters(q, dParams);

			var signer = new ECGost3410Signer();
			signer.Init(false, parameters);

			var digest = new Gost3411Digest();

			digest.BlockUpdate(buffer, 0, length);
			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			return signer.VerifySignature(hash, new BigInteger(1, signature, 32, 32), new BigInteger(1, signature, 0, 32));
		}

		private bool VerifyEcDsa(IDigest digest, X9ECParameters curveParameter, byte[] buffer, int length, byte[] signature)
		{
			int digestSize = digest.GetDigestSize();

			ECDomainParameters dParams = new ECDomainParameters(
				curveParameter.Curve,
				curveParameter.G,
				curveParameter.N,
				curveParameter.H,
				curveParameter.GetSeed());

			ECPoint q = dParams.Curve.CreatePoint(new BigInteger(1, PublicKey, 0, digestSize), new BigInteger(1, PublicKey, digestSize, digestSize), false);

			ECPublicKeyParameters parameters = new ECPublicKeyParameters(q, dParams);

			var signer = new ECDsaSigner();
			signer.Init(false, parameters);

			digest.BlockUpdate(buffer, 0, length);
			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);

			return signer.VerifySignature(hash, new BigInteger(1, signature, 0, digestSize), new BigInteger(1, signature, digestSize, digestSize));
		}

		/// <summary>
		///   Creates a new signing key pair
		/// </summary>
		/// <param name="name">The name of the key or zone</param>
		/// <param name="recordClass">The record class of the DnsKeyRecord</param>
		/// <param name="timeToLive">The TTL in seconds to the DnsKeyRecord</param>
		/// <param name="flags">The Flags of the DnsKeyRecord</param>
		/// <param name="protocol">The protocol version</param>
		/// <param name="algorithm">The key algorithm</param>
		/// <param name="keyStrength">The key strength or 0 for default strength</param>
		/// <returns></returns>
		public static DnsKeyRecord CreateSigningKey(DomainName name, RecordClass recordClass, int timeToLive, DnsKeyFlags flags, byte protocol, DnsSecAlgorithm algorithm, int keyStrength = 0)
		{
			byte[] privateKey;
			byte[] publicKey;

			switch (algorithm)
			{
				case DnsSecAlgorithm.RsaSha1:
				case DnsSecAlgorithm.RsaSha1Nsec3Sha1:
				case DnsSecAlgorithm.RsaSha256:
				case DnsSecAlgorithm.RsaSha512:
					if (keyStrength == 0)
						keyStrength = (flags == (DnsKeyFlags.Zone | DnsKeyFlags.SecureEntryPoint)) ? 2048 : 1024;

					RsaKeyPairGenerator rsaKeyGen = new RsaKeyPairGenerator();
					rsaKeyGen.Init(new KeyGenerationParameters(_secureRandom, keyStrength));
					var rsaKey = rsaKeyGen.GenerateKeyPair();
					privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsaKey.Private).GetDerEncoded();
					var rsaPublicKey = (RsaKeyParameters) rsaKey.Public;
					var rsaExponent = rsaPublicKey.Exponent.ToByteArrayUnsigned();
					var rsaModulus = rsaPublicKey.Modulus.ToByteArrayUnsigned();

					int offset = 1;
					if (rsaExponent.Length > 255)
					{
						publicKey = new byte[3 + rsaExponent.Length + rsaModulus.Length];
						DnsMessageBase.EncodeUShort(publicKey, ref offset, (ushort) publicKey.Length);
					}
					else
					{
						publicKey = new byte[1 + rsaExponent.Length + rsaModulus.Length];
						publicKey[0] = (byte) rsaExponent.Length;
					}
					DnsMessageBase.EncodeByteArray(publicKey, ref offset, rsaExponent);
					DnsMessageBase.EncodeByteArray(publicKey, ref offset, rsaModulus);
					break;

				case DnsSecAlgorithm.Dsa:
				case DnsSecAlgorithm.DsaNsec3Sha1:
					if (keyStrength == 0)
						keyStrength = 1024;

					DsaParametersGenerator dsaParamsGen = new DsaParametersGenerator();
					dsaParamsGen.Init(keyStrength, 12, _secureRandom);
					DsaKeyPairGenerator dsaKeyGen = new DsaKeyPairGenerator();
					dsaKeyGen.Init(new DsaKeyGenerationParameters(_secureRandom, dsaParamsGen.GenerateParameters()));
					var dsaKey = dsaKeyGen.GenerateKeyPair();
					privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(dsaKey.Private).GetDerEncoded();
					var dsaPublicKey = (DsaPublicKeyParameters) dsaKey.Public;

					var dsaY = dsaPublicKey.Y.ToByteArrayUnsigned();
					var dsaP = dsaPublicKey.Parameters.P.ToByteArrayUnsigned();
					var dsaQ = dsaPublicKey.Parameters.Q.ToByteArrayUnsigned();
					var dsaG = dsaPublicKey.Parameters.G.ToByteArrayUnsigned();
					var dsaT = (byte) ((dsaY.Length - 64) / 8);

					publicKey = new byte[21 + 3 * dsaY.Length];
					publicKey[0] = dsaT;
					dsaQ.CopyTo(publicKey, 1);
					dsaP.CopyTo(publicKey, 21);
					dsaG.CopyTo(publicKey, 21 + dsaY.Length);
					dsaY.CopyTo(publicKey, 21 + 2 * dsaY.Length);
					break;

				case DnsSecAlgorithm.EccGost:
					ECDomainParameters gostEcDomainParameters = ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);

					var gostKeyGen = new ECKeyPairGenerator();
					gostKeyGen.Init(new ECKeyGenerationParameters(gostEcDomainParameters, _secureRandom));

					var gostKey = gostKeyGen.GenerateKeyPair();
					privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(gostKey.Private).GetDerEncoded();
					var gostPublicKey = (ECPublicKeyParameters) gostKey.Public;

					publicKey = new byte[64];

					gostPublicKey.Q.X.ToBigInteger().ToByteArrayUnsigned().CopyTo(publicKey, 32);
					gostPublicKey.Q.Y.ToBigInteger().ToByteArrayUnsigned().CopyTo(publicKey, 0);

					publicKey = publicKey.Reverse().ToArray();
					break;

				case DnsSecAlgorithm.EcDsaP256Sha256:
				case DnsSecAlgorithm.EcDsaP384Sha384:
					int ecDsaDigestSize;
					X9ECParameters ecDsaCurveParameter;

					if (algorithm == DnsSecAlgorithm.EcDsaP256Sha256)
					{
						ecDsaDigestSize = new Sha256Digest().GetDigestSize();
						ecDsaCurveParameter = NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
					}
					else
					{
						ecDsaDigestSize = new Sha384Digest().GetDigestSize();
						ecDsaCurveParameter = NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1);
					}

					ECDomainParameters ecDsaP384EcDomainParameters = new ECDomainParameters(
						ecDsaCurveParameter.Curve,
						ecDsaCurveParameter.G,
						ecDsaCurveParameter.N,
						ecDsaCurveParameter.H,
						ecDsaCurveParameter.GetSeed());

					var ecDsaKeyGen = new ECKeyPairGenerator();
					ecDsaKeyGen.Init(new ECKeyGenerationParameters(ecDsaP384EcDomainParameters, _secureRandom));

					var ecDsaKey = ecDsaKeyGen.GenerateKeyPair();
					privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ecDsaKey.Private).GetDerEncoded();
					var ecDsaPublicKey = (ECPublicKeyParameters) ecDsaKey.Public;

					publicKey = new byte[ecDsaDigestSize * 2];

					ecDsaPublicKey.Q.X.ToBigInteger().ToByteArrayUnsigned().CopyTo(publicKey, 0);
					ecDsaPublicKey.Q.Y.ToBigInteger().ToByteArrayUnsigned().CopyTo(publicKey, ecDsaDigestSize);
					break;

				default:
					throw new NotSupportedException();
			}

			return new DnsKeyRecord(name, recordClass, timeToLive, flags, protocol, algorithm, publicKey, privateKey);
		}
	}
}