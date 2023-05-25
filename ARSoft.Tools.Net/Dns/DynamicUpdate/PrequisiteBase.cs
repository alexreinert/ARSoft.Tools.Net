#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
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
using System.Xml.Linq;

namespace ARSoft.Tools.Net.Dns.DynamicUpdate;

/// <summary>
///   Base class for prequisites of dynamic dns updates
/// </summary>
public abstract class PrequisiteBase
{
	/// <summary>
	///   Domain name
	/// </summary>
	public DomainName Name { get; private set; }

	protected virtual int MaximumRecordDataLength => 0;

	internal int MaximumLength => Name.MaximumRecordDataLength + 12 + MaximumRecordDataLength;

	protected abstract RecordType RecordTypeInternal { get; }

	protected abstract RecordClass RecordClassInternal { get; }

	protected PrequisiteBase(DomainName name)
	{
		_ = name ?? throw new ArgumentNullException(nameof(name));

		Name = name;
	}

	internal void Encode(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical = false)
	{
		EncodeRecordHeader(messageData, ref currentPosition, domainNames, useCanonical);
		EncodeRecordBody(messageData, ref currentPosition, domainNames, useCanonical);
	}

	internal void EncodeRecordHeader(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
	{
		DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, Name, domainNames, useCanonical);
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordTypeInternal);
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordClassInternal);
		DnsMessageBase.EncodeInt(messageData, ref currentPosition, 0); // TTL
	}

	internal void EncodeRecordBody(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
	{
		int recordDataOffset = currentPosition + 2;
		EncodeRecordData(messageData, ref recordDataOffset, domainNames, useCanonical);
		EncodeRecordLength(messageData, ref currentPosition, domainNames, recordDataOffset);
	}

	internal void EncodeRecordLength(IList<byte> messageData, ref int recordDataOffset, Dictionary<DomainName, ushort> domainNames, int recordPosition)
	{
		DnsMessageBase.EncodeUShort(messageData, ref recordDataOffset, (ushort) (recordPosition - recordDataOffset - 2));
		recordDataOffset = recordPosition;
	}

	protected virtual void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical) { }

	internal static PrequisiteBase ParsePrequisiteFromMessage(IList<byte> resultData, ref int currentPosition)
	{
		var startPosition = currentPosition;
		var name = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
		var recordType = (RecordType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);

		var recordClass = (RecordClass) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
		var timeToLive = DnsMessageBase.ParseInt(resultData, ref currentPosition);
		var recordDataLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);

		var recordDataPosition = currentPosition;
		currentPosition += recordDataLength;

		if ((recordClass == RecordClass.Any) && (recordType == RecordType.Any))
		{
			return new NameIsInUsePrequisite(name);
		}
		else if ((recordClass == RecordClass.Any) && (recordDataLength == 0))
		{
			return new RecordExistsValueIndependantPrequisite(name, recordType);
		}
		else if ((recordClass == RecordClass.None) && (recordType == RecordType.Any))
		{
			return new NameIsNotInUsePrequisite(name);
		}
		else if ((recordClass == RecordClass.None) && (recordDataLength == 0))
		{
			return new RecordNotExistsPrequisite(name, recordType);
		}
		else
		{
			var record = DnsRecordBase.ParseRecordFromBinary(startPosition, name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
			return new RecordExistsValueDependantPrequisite(record);
		}
	}

	internal static PrequisiteBase ParseRfc8427Json(JsonElement headerJson, JsonElement bodyJson)
	{
		var rname = DomainName.Root;
		var rclass = RecordClass.INet;
		var rtype = RecordType.Invalid;
		var ttl = 0;

		foreach (var prop in headerJson.EnumerateObject())
		{
			switch (prop.Name)
			{
				case "NAME":
					rname = DomainName.Parse(prop.Value.GetString() ?? String.Empty);
					break;
				case "TYPE":
					rtype = (RecordType) prop.Value.GetUInt16();
					break;
				case "TYPEname":
					rtype = RecordTypeHelper.ParseShortString(prop.Value.GetString() ?? String.Empty);
					break;
				case "CLASS":
					rclass = (RecordClass) prop.Value.GetUInt16();
					break;
				case "CLASSname":
					rclass = RecordClassHelper.ParseShortString(prop.Value.GetString() ?? String.Empty);
					break;
				case "TTL":
					ttl = prop.Value.GetInt32();
					break;
			}
		}

		if ((rclass == RecordClass.Any) && (rtype == RecordType.Any))
		{
			return new NameIsInUsePrequisite(rname);
		}
		else if ((rclass == RecordClass.None) && (rtype == RecordType.Any))
		{
			return new NameIsNotInUsePrequisite(rname);
		}
		else if (bodyJson.TryGetProperty("rdata" + rtype.ToShortString(), out var rtextjson) && !String.IsNullOrWhiteSpace(rtextjson.GetString()))
		{
			var stringRepresentation =
				rtextjson.GetString()!
					.SplitWithQuoting(new[] { ' ', '\t' }, true, true)
					.Select(x => x.FromMasterfileLabelRepresentation())
					.ToArray();

			var record = DnsRecordBase.ParseFromStringRepresentation(rname, rtype, rclass, ttl, DomainName.Root, stringRepresentation);
			return new RecordExistsValueDependantPrequisite(record);
		}
		else if (bodyJson.TryGetProperty("RDATAHEX", out var rhexjson) && !String.IsNullOrWhiteSpace(rhexjson.GetString()))
		{
			var binData = rhexjson.GetString()!.FromBase16String();
			var record = DnsRecordBase.ParseRecordFromBinary(0, rname, rtype, rclass, ttl, binData, 0, binData.Length);
			return new RecordExistsValueDependantPrequisite(record);
		}
		else if (rclass == RecordClass.Any)
		{
			return new RecordExistsValueIndependantPrequisite(rname, rtype);
		}
		else if (rclass == RecordClass.None)
		{
			return new RecordNotExistsPrequisite(rname, rtype);
		}
		else
		{
			var record = DnsRecordBase.ParseRecordFromBinary(0, rname, rtype, rclass, ttl, Array.Empty<byte>(), 0, 0);
			return new RecordExistsValueDependantPrequisite(record);
		}
	}

	protected internal void WriteRfc8427Json(Utf8JsonWriter writer, JsonSerializerOptions options)
	{
		writer.WriteStartObject();

		writer.WriteString("NAME", Name.ToString(true));
		writer.WriteNumber("TYPE", (ushort)RecordTypeInternal);
		writer.WriteString("TYPEname", RecordTypeInternal.ToShortString());
		writer.WriteNumber("CLASS", (ushort)RecordClassInternal);
		writer.WriteString("CLASSname", RecordClassInternal.ToShortString());
		writer.WriteNumber("TTL", (ushort)0);

		var rdata = new byte[MaximumRecordDataLength];
		int pos = 0;
		EncodeRecordData(rdata, ref pos, new Dictionary<DomainName, ushort>(), false);
		writer.WriteNumber("RDLENGTH", pos);
		writer.WriteString("RDATAHEX", rdata.ToBase16String(0, pos));

		writer.WriteEndObject();
	}
}