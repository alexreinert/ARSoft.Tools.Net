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
using System.Text.Json;
using System.Xml.Linq;

namespace ARSoft.Tools.Net.Dns.DynamicUpdate;

/// <summary>
///   Base update action of dynamic dns update
/// </summary>
public abstract class UpdateBase
{
	/// <summary>
	///   Domain name
	/// </summary>
	public DomainName Name { get; private set; }

	protected virtual int MaximumRecordDataLength => 0;

	internal int MaximumLength => Name.MaximumRecordDataLength + 12 + MaximumRecordDataLength;

	protected abstract RecordType RecordTypeInternal { get; }

	protected abstract RecordClass RecordClassInternal { get; }

	protected abstract int TimeToLive { get; }

	protected UpdateBase(DomainName name)
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
		DnsMessageBase.EncodeInt(messageData, ref currentPosition, TimeToLive);
	}

	internal void EncodeRecordBody(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
	{
		var recordDataOffset = currentPosition + 2;
		EncodeRecordData(messageData, ref recordDataOffset, domainNames, useCanonical);
		EncodeRecordLength(messageData, ref currentPosition, domainNames, recordDataOffset);
	}

	internal void EncodeRecordLength(IList<byte> messageData, ref int recordDataOffset, Dictionary<DomainName, ushort> domainNames, int recordPosition)
	{
		DnsMessageBase.EncodeUShort(messageData, ref recordDataOffset, (ushort) (recordPosition - recordDataOffset - 2));
		recordDataOffset = recordPosition;
	}

	protected virtual void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical) { }

	internal static UpdateBase ParseUpdateFromMessage(IList<byte> resultData, ref int currentPosition)
	{
		var startPosition = currentPosition;
		var name = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
		var recordType = (RecordType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);

		var recordClass = (RecordClass) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
		var timeToLive = DnsMessageBase.ParseInt(resultData, ref currentPosition);
		var recordDataLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);

		var recordDataPosition = currentPosition;
		currentPosition += recordDataLength;

		if (timeToLive == 0)
		{
			if (recordDataLength == 0)
			{
				return new DeleteAllRecordsUpdate(name, recordType);
			}
			else
			{
				var record = DnsRecordBase.ParseRecordFromBinary(startPosition, name, recordType, RecordClass.INet, timeToLive, resultData, recordDataPosition, recordDataLength);
				return new DeleteRecordUpdate(record);
			}
		}
		else
		{
			var record = DnsRecordBase.ParseRecordFromBinary(startPosition, name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
			return new AddRecordUpdate(record);
		}
	}

	internal static UpdateBase ParseRfc8427Json(JsonElement headerJson, JsonElement bodyJson)
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

		if (ttl == 0)
		{
			if (bodyJson.TryGetProperty("rdata" + rtype.ToShortString(), out var rtextjson) && !String.IsNullOrWhiteSpace(rtextjson.GetString()))
			{
				var stringRepresentation =
					rtextjson.GetString()!
						.SplitWithQuoting(new[] { ' ', '\t' }, true, true)
						.Select(x => x.FromMasterfileLabelRepresentation())
						.ToArray();

				var record = DnsRecordBase.ParseFromStringRepresentation(rname, rtype, RecordClass.INet, ttl, DomainName.Root, stringRepresentation);
				return new DeleteRecordUpdate(record);
			}
			else if (bodyJson.TryGetProperty("RDATAHEX", out var rhexjson) && !String.IsNullOrWhiteSpace(rhexjson.GetString()))
			{
				var binData = rhexjson.GetString()!.FromBase16String();
				var record = DnsRecordBase.ParseRecordFromBinary(0, rname, rtype, RecordClass.INet, ttl, binData, 0, binData.Length);
				return new DeleteRecordUpdate(record);
			}
			else
			{
				return new DeleteAllRecordsUpdate(rname, rtype);
			}
		}
		else if (bodyJson.TryGetProperty("rdata" + rtype.ToShortString(), out var rtextjson) && !String.IsNullOrWhiteSpace(rtextjson.GetString()))
		{
			var stringRepresentation =
				rtextjson.GetString()!
					.SplitWithQuoting(new[] { ' ', '\t' }, true, true)
					.Select(x => x.FromMasterfileLabelRepresentation())
					.ToArray();

			var record = DnsRecordBase.ParseFromStringRepresentation(rname, rtype, rclass, ttl, DomainName.Root, stringRepresentation);
			return new AddRecordUpdate(record);
		}
		else if (bodyJson.TryGetProperty("RDATAHEX", out var rhexjson) && !String.IsNullOrWhiteSpace(rhexjson.GetString()))
		{
			var binData = rhexjson.GetString()!.FromBase16String();
			var record = DnsRecordBase.ParseRecordFromBinary(0, rname, rtype, rclass, ttl, binData, 0, binData.Length);
			return new AddRecordUpdate(record);
		}
		else
		{
			var record = DnsRecordBase.ParseRecordFromBinary(0, rname, rtype, rclass, ttl, Array.Empty<byte>(), 0, 0);
			return new AddRecordUpdate(record);
		}
	}

	protected internal void WriteRfc8427Json(Utf8JsonWriter writer, JsonSerializerOptions options)
	{
		writer.WriteStartObject();

		writer.WriteString("NAME", Name.ToString(true));
		writer.WriteNumber("TYPE", (ushort) RecordTypeInternal);
		writer.WriteString("TYPEname", RecordTypeInternal.ToShortString());
		writer.WriteNumber("CLASS", (ushort) RecordClassInternal);
		writer.WriteString("CLASSname", RecordClassInternal.ToShortString());
		writer.WriteNumber("TTL", (ushort) TimeToLive);

		var rdata = new byte[MaximumRecordDataLength];
		int pos = 0;
		EncodeRecordData(rdata, ref pos, new Dictionary<DomainName, ushort>(), false);
		writer.WriteNumber("RDLENGTH", pos);
		writer.WriteString("RDATAHEX", rdata.ToBase16String(0, pos));

		writer.WriteEndObject();
	}
}