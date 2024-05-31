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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Child DNS Key record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc7344.html">RFC 7344</a>.
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
		public byte[]? PrivateKey { get; private set; }

		/// <summary>
		///   <para>Record holds a DNS zone key</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3757.html">RFC 3757</a>.
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
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3757.html">RFC 3757</a>.
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
		///     <a href="https://www.rfc-editor.org/rfc/rfc5011.html">RFC 5011</a>.
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
		///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>.
		///   </para>
		/// </summary>
		/// <returns>The key tag</returns>
		public ushort CalculateKeyTag()
		{
#pragma warning disable 0612
			if (Algorithm == DnsSecAlgorithm.RsaMd5)
#pragma warning restore 0612
				return (ushort) (PublicKey[PublicKey.Length - 4] & PublicKey[PublicKey.Length - 3] << 8);

			var buffer = new byte[MaximumRecordDataLength];
			int currentPosition = 0;
			EncodeRecordData(buffer, ref currentPosition, null, false);

			ulong ac = 0;

			for (int i = 0; i < currentPosition; ++i)
			{
				ac += ((i & 1) == 1) ? buffer[i] : (ulong) buffer[i] << 8;
			}

			ac += (ac >> 16) & 0xFFFF;

			ushort res = (ushort) (ac & 0xffff);

			return res;
		}

		internal CDnsKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Flags = (DnsKeyFlags) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Protocol = resultData[currentPosition++];
			Algorithm = (DnsSecAlgorithm) resultData[currentPosition++];
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length - 4);
		}

		internal CDnsKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length < 4)
				throw new FormatException();

			Flags = (DnsKeyFlags) UInt16.Parse(stringRepresentation[0]);
			Protocol = Byte.Parse(stringRepresentation[1]);
			Algorithm = (DnsSecAlgorithm) Byte.Parse(stringRepresentation[2]);
			PublicKey = String.Join(String.Empty, stringRepresentation.Skip(3)).FromBase64String();
		}

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
			: this(name, recordClass, timeToLive, flags, protocol, algorithm, publicKey, null) { }

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
		public CDnsKeyRecord(DomainName name, RecordClass recordClass, int timeToLive, DnsKeyFlags flags, byte protocol, DnsSecAlgorithm algorithm, byte[] publicKey, byte[]? privateKey)
			: base(name, RecordType.CDnsKey, recordClass, timeToLive)
		{
			Flags = flags;
			Protocol = protocol;
			Algorithm = algorithm;
			PublicKey = publicKey;
			PrivateKey = privateKey;
		}

		internal override string RecordDataToString()
		{
			return (ushort) Flags
			       + " " + Protocol
			       + " " + (byte) Algorithm
			       + " " + PublicKey.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength => 4 + PublicKey.Length;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Flags);
			messageData[currentPosition++] = Protocol;
			messageData[currentPosition++] = (byte) Algorithm;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}