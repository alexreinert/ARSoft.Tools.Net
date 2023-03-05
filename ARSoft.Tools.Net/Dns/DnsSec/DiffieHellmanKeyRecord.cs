﻿#region Copyright and License
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
	///   <para>Security Key record using Diffie Hellman algorithm</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
	///     ,
	///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>
	///     ,
	///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>
	///     and
	///     <a href="https://www.rfc-editor.org/rfc/rfc2930.html">RFC 2930</a>.
	///   </para>
	/// </summary>
	public class DiffieHellmanKeyRecord : KeyRecordBase
	{
		/// <summary>
		///   Binary data of the prime of the key
		/// </summary>
		public byte[] Prime { get; private set; }

		/// <summary>
		///   Binary data of the generator of the key
		/// </summary>
		public byte[] Generator { get; private set; }

		/// <summary>
		///   Binary data of the public value
		/// </summary>
		public byte[] PublicValue { get; private set; }

		internal DiffieHellmanKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive, resultData, currentPosition, length)
		{
			int primeLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Prime = DnsMessageBase.ParseByteData(resultData, ref currentPosition, primeLength);
			int generatorLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Generator = DnsMessageBase.ParseByteData(resultData, ref currentPosition, generatorLength);
			int publicValueLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			PublicValue = DnsMessageBase.ParseByteData(resultData, ref currentPosition, publicValueLength);
		}

		/// <summary>
		///   Creates a new instance of the DiffieHellmanKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="flags"> Flags of the key </param>
		/// <param name="protocol"> Protocol for which the key is used </param>
		/// <param name="prime"> Binary data of the prime of the key </param>
		/// <param name="generator"> Binary data of the generator of the key </param>
		/// <param name="publicValue"> Binary data of the public value </param>
		public DiffieHellmanKeyRecord(DomainName name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, byte[] prime, byte[] generator, byte[] publicValue)
#pragma warning disable 0612
			: base(name, recordClass, timeToLive, flags, protocol, DnsSecAlgorithm.DiffieHellman)
#pragma warning restore 0612
		{
			Prime = prime ?? new byte[] { };
			Generator = generator ?? new byte[] { };
			PublicValue = publicValue ?? new byte[] { };
		}

		protected override string PublicKeyToString()
		{
			byte[] publicKey = new byte[MaximumPublicKeyLength];
			int currentPosition = 0;

			EncodePublicKey(publicKey, ref currentPosition, null);

			return publicKey[0..currentPosition].ToBase64String();
		}

		protected override int MaximumPublicKeyLength => 3 + Prime.Length + Generator.Length + PublicValue.Length;

		protected override void EncodePublicKey(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Prime.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Prime);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Generator.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Generator);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) PublicValue.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicValue);
		}
	}
}