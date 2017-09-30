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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>OpenPGP Key</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/draft-ietf-dane-openpgpkey">draft-ietf-dane-openpgpkey</see>
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public class OpenPGPKeyRecord : DnsRecordBase
	{
		/// <summary>
		///   The Public Key
		/// </summary>
		public byte[] PublicKey { get; private set; }

		internal OpenPGPKeyRecord() {}

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

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length == 0)
				throw new NotSupportedException();

			PublicKey = String.Join(String.Empty, stringRepresentation).FromBase64String();
		}

		internal override string RecordDataToString()
		{
			return PublicKey.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength => PublicKey.Length;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}