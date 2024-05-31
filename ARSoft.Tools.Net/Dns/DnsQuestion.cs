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
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   A single entry of the Question section of a dns query
/// </summary>
public class DnsQuestion : DnsMessageEntryBase, IEquatable<DnsQuestion>
{
	/// <summary>
	///   Creates a new instance of the DnsQuestion class
	/// </summary>
	/// <param name="name"> Domain name </param>
	/// <param name="recordType"> Record type </param>
	/// <param name="recordClass"> Record class </param>
	public DnsQuestion(DomainName name, RecordType recordType, RecordClass recordClass) : base(name, recordType, recordClass) { }

	internal override int MaximumLength => Name.MaximumRecordDataLength + 6;

	internal void Encode(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames)
	{
		DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, Name, domainNames, false);
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordType);
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordClass);
	}

	internal static DnsQuestion Parse(IList<byte> data, ref int currentPosition)
	{
		return new DnsQuestion(
			DnsMessageBase.ParseDomainName(data, ref currentPosition),
			(RecordType) DnsMessageBase.ParseUShort(data, ref currentPosition),
			(RecordClass) DnsMessageBase.ParseUShort(data, ref currentPosition));
	}

	internal static DnsQuestion ParseRfc8427Json(JsonElement json)
	{
		var qname = DomainName.Root;
		var qclass = RecordClass.INet;
		var qtype = RecordType.Invalid;

		foreach (var prop in json.EnumerateObject())
		{
			switch (prop.Name)
			{
				case "NAME":
					qname = DomainName.Parse(prop.Value.GetString() ?? String.Empty);
					break;
				case "TYPE":
					qtype = (RecordType) prop.Value.GetUInt16();
					break;
				case "TYPEname":
					qtype = RecordTypeHelper.ParseShortString(prop.Value.GetString() ?? String.Empty);
					break;
				case "CLASS":
					qclass = (RecordClass) prop.Value.GetUInt16();
					break;
				case "CLASSname":
					qclass = RecordClassHelper.ParseShortString(prop.Value.GetString() ?? String.Empty);
					break;
			}
		}

		return new DnsQuestion(qname, qtype, qclass);
	}

	protected internal override void WriteRfc8427Json(Utf8JsonWriter writer, JsonSerializerOptions options)
	{
		writer.WriteStartObject();

		writer.WriteString("NAME", Name.ToString(true));
		writer.WriteNumber("TYPE", (ushort) RecordType);
		writer.WriteString("TYPEname", RecordType.ToShortString());
		writer.WriteNumber("CLASS", (ushort) RecordClass);
		writer.WriteString("CLASSname", RecordClass.ToShortString());

		writer.WriteEndObject();
	}

	private int? _hashCode;

	[SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
	public override int GetHashCode()
	{
		if (!_hashCode.HasValue)
		{
			_hashCode = ToString().GetHashCode();
		}

		return _hashCode.Value;
	}

	public override bool Equals(object? obj)
	{
		return Equals(obj as DnsQuestion);
	}

	public bool Equals(DnsQuestion? other)
	{
		if (other == null)
			return false;

		return base.Equals(other);
	}
}