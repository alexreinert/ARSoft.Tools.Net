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
	///   <para>CAA</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc6844.html">RFC 6844</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public class CAARecord : DnsRecordBase
	{
		/// <summary>
		///   The flags
		/// </summary>
		public byte Flags { get; private set; }

		/// <summary>
		///   The name of the tag
		/// </summary>
		public string Tag { get; private set; }

		/// <summary>
		///   The value of the tag
		/// </summary>
		public string Value { get; private set; }

		internal CAARecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Flags = resultData[currentPosition++];
			Tag = DnsMessageBase.ParseText(resultData, ref currentPosition);
			Value = DnsMessageBase.ParseText(resultData, ref currentPosition, length - (2 + Tag.Length));
		}

		internal CAARecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 3)
				throw new FormatException();

			Flags = Byte.Parse(stringRepresentation[0]);
			Tag = stringRepresentation[1];
			Value = stringRepresentation[2];
		}

		/// <summary>
		///   Creates a new instance of the CAARecord class
		/// </summary>
		/// <param name="name"> Name of the zone </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="flags">The flags</param>
		/// <param name="tag">The name of the tag</param>
		/// <param name="value">The value of the tag</param>
		public CAARecord(DomainName name, int timeToLive, byte flags, string tag, string value)
			: base(name, RecordType.CAA, RecordClass.INet, timeToLive)
		{
			Flags = flags;
			Tag = tag;
			Value = value;
		}

		internal override string RecordDataToString()
		{
			return Flags + " " + Tag.ToMasterfileLabelRepresentation() + " " + Value.ToMasterfileLabelRepresentation();
		}

		protected internal override int MaximumRecordDataLength => 2 + Tag.Length + Value.Length;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			messageData[currentPosition++] = Flags;
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Tag);
			DnsMessageBase.EncodeTextWithoutLength(messageData, ref currentPosition, Value);
		}
	}
}