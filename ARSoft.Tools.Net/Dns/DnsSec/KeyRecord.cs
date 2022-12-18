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
	///   <para>Security Key record</para>
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
	public class KeyRecord : KeyRecordBase
	{
		/// <summary>
		///   Binary data of the public key
		/// </summary>
		public byte[] PublicKey { get; private set; }

		internal KeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive, resultData, currentPosition, length)
		{
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length - 4);
		}

		internal KeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, RecordClass.Any, 0, 0, ProtocolType.Any, DnsSecAlgorithm.Indirect)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		///   Creates of new instance of the KeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="flags"> Flags of the key </param>
		/// <param name="protocol"> Protocol for which the key is used </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="publicKey"> Binary data of the public key </param>
		public KeyRecord(DomainName name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, DnsSecAlgorithm algorithm, byte[] publicKey)
			: base(name, recordClass, timeToLive, flags, protocol, algorithm)
		{
			PublicKey = publicKey ?? new byte[] { };
		}

		protected override string PublicKeyToString()
		{
			return PublicKey.ToBase64String();
		}

		protected override int MaximumPublicKeyLength => PublicKey.Length;

		protected override void EncodePublicKey(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}