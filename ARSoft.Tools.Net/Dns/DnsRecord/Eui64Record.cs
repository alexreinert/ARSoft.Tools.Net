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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>EUI64</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc7043.html">RFC 7043</a>.
	///   </para>
	/// </summary>
	public class Eui64Record : DnsRecordBase
	{
		/// <summary>
		///   IP address of the host
		/// </summary>
		public byte[] Address { get; private set; }

		internal Eui64Record(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Address = DnsMessageBase.ParseByteData(resultData, ref currentPosition, 8);
		}

		internal Eui64Record(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 1)
				throw new NotSupportedException();

			Address = stringRepresentation[0].Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();

			if (Address.Length != 8)
				throw new NotSupportedException();
		}

		/// <summary>
		///   Creates a new instance of the Eui48Record class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="address"> The EUI48 address</param>
		public Eui64Record(DomainName name, int timeToLive, byte[] address)
			: base(name, RecordType.Eui64, RecordClass.INet, timeToLive)
		{
			Address = address ?? new byte[8];
		}

		internal override string RecordDataToString()
		{
			return String.Join("-", Address.Select(x => x.ToString("x2")).ToArray());
		}

		protected internal override int MaximumRecordDataLength => 8;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Address);
		}
	}
}