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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Child DNS Key record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc7344">RFC 7344</see>
	///   </para>
	/// </summary>
	public class CDnsKeyRecord : DnsRecordBase
	{
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
		public byte[] PrivateKey { get; private set; }

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

		internal CDnsKeyRecord() {}

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
		public CDnsKeyRecord(DomainName name, RecordClass recordClass, int timeToLive, DnsKeyFlags flags, byte protocol, DnsSecAlgorithm algorithm, byte[] publicKey)
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
		public CDnsKeyRecord(DomainName name, RecordClass recordClass, int timeToLive, DnsKeyFlags flags, byte protocol, DnsSecAlgorithm algorithm, byte[] publicKey, byte[] privateKey)
			: base(name, RecordType.CDnsKey, recordClass, timeToLive)
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
	}
}