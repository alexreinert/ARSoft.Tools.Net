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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>OpenPGP Key</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc7929.html">RFC 7929</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public class OpenPGPKeyRecord : DnsRecordBase
	{
		/// <summary>
		///   The Public Key
		/// </summary>
		public byte[] PublicKey { get; private set; }

		internal OpenPGPKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length);
		}

		internal OpenPGPKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length == 0)
				throw new NotSupportedException();

			PublicKey = String.Join(String.Empty, stringRepresentation).FromBase64String();
		}

		/// <summary>
		///   Creates a new instance of the OpenPGPKeyRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="publicKey"> The Public Key</param>
		public OpenPGPKeyRecord(DomainName name, int timeToLive, byte[] publicKey)
			: base(name, RecordType.OpenPGPKey, RecordClass.INet, timeToLive)
		{
			PublicKey = publicKey ?? new byte[] { };
		}

		internal override string RecordDataToString()
		{
			return PublicKey.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength => PublicKey.Length;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}