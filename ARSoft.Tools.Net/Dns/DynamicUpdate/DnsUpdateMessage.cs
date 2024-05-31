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
using System.Text.Json.Serialization;
using System.Xml.Linq;

namespace ARSoft.Tools.Net.Dns.DynamicUpdate;

/// <summary>
///   <para>Dynamic DNS update message</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc2136.html">RFC 2136</a>.
///   </para>
/// </summary>
[JsonConverter(typeof(Rfc8427JsonConverter<DnsUpdateMessage>))]
public class DnsUpdateMessage : DnsMessageBase
{
	/// <summary>
	///   Parses a the contents of a byte array as DnsUpdateMessage
	/// </summary>
	/// <param name="data">Buffer, that contains the message data</param>
	/// <returns>A new instance of the DnsUpdateMessage class</returns>
	public static DnsUpdateMessage Parse(byte[] data)
	{
		return Parse<DnsUpdateMessage>(data);
	}

	/// <summary>
	///   Creates a new instance of the DnsUpdateMessage class
	/// </summary>
	public DnsUpdateMessage()
	{
		OperationCodeInternal = OperationCode.Update;
	}

	private List<PrequisiteBase> _prequisites = new List<PrequisiteBase>();
	private List<UpdateBase> _updates = new List<UpdateBase>();

	/// <summary>
	///   Gets or sets the zone name
	/// </summary>
	public DomainName ZoneName { get; set; } = DomainName.Root;

	/// <summary>
	///   Gets or sets the entries in the prerequisites section
	/// </summary>
	public List<PrequisiteBase> Prequisites
	{
		get { return _prequisites ??= new List<PrequisiteBase>(); }
		set { _prequisites = value; }
	}

	/// <summary>
	///   Gets or sets the entries in the update section
	/// </summary>
	public List<UpdateBase> Updates
	{
		get { return _updates ??= new List<UpdateBase>(); }
		set { _updates = value; }
	}

	/// <summary>
	///   Creates a new instance of the DnsUpdateMessage as response to the current instance
	/// </summary>
	/// <returns>A new instance of the DnsUpdateMessage as response to the current instance</returns>
	public DnsUpdateMessage CreateResponseInstance()
	{
		DnsUpdateMessage result = new DnsUpdateMessage()
		{
			TransactionID = TransactionID,
			IsEDnsEnabled = IsEDnsEnabled,
			IsQuery = false,
			ZoneName = ZoneName,
		};

		if (IsEDnsEnabled)
		{
			result.EDnsOptions!.Version = EDnsOptions!.Version;
			result.EDnsOptions!.UdpPayloadSize = EDnsOptions!.UdpPayloadSize;
		}

		return result;
	}

	protected internal override DnsMessageBase CreateFailureResponse()
	{
		DnsUpdateMessage msg = CreateResponseInstance();
		msg.ReturnCode = ReturnCode.ServerFailure;
		return msg;
	}

	internal override bool IsReliableSendingRequested => false;

	internal override bool IsReliableResendingRequested => false;

	internal override bool IsNextMessageWaiting(bool isSubsequentResponseMessage)
	{
		return false;
	}

	protected override void SetQuestionSection(List<DnsQuestion> questions)
	{
		ZoneName = questions.Count == 1 && questions[0].RecordType == RecordType.Soa && questions[0].RecordClass == RecordClass.INet ? questions[0].Name : DomainName.Root;
	}

	protected override void ParseAnswerSection(IList<byte> data, ref int currentPosition, int recordCount)
	{
		for (int i = 0; i < recordCount; i++)
		{
			Prequisites.Add(PrequisiteBase.ParsePrequisiteFromMessage(data, ref currentPosition));
		}
	}

	protected override void ParseAuthoritySection(IList<byte> data, ref int currentPosition, int recordCount)
	{
		for (int i = 0; i < recordCount; i++)
		{
			Updates.Add(UpdateBase.ParseUpdateFromMessage(data, ref currentPosition));
		}
	}

	protected override int GetSectionsMaxLength()
	{
		return 12
		       + ZoneName.MaximumRecordDataLength + 6
		       + Prequisites.Sum(record => record.MaximumLength)
		       + Updates.Sum(record => record.MaximumLength)
		       + AdditionalRecords.Sum(record => record.MaximumLength);
	}

	protected override void EncodeSections(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort> domainNames)
	{
		EncodeUShort(messageData, ref currentPosition, 1);
		EncodeUShort(messageData, ref currentPosition, (ushort) Prequisites.Count);
		EncodeUShort(messageData, ref currentPosition, (ushort) Updates.Count);
		EncodeUShort(messageData, ref currentPosition, (ushort) AdditionalRecords.Count);

		new DnsQuestion(ZoneName, RecordType.Soa, RecordClass.INet).Encode(messageData, ref currentPosition, domainNames);
		foreach (PrequisiteBase prequisite in Prequisites)
		{
			prequisite.Encode(messageData, ref currentPosition, domainNames);
		}

		foreach (UpdateBase update in Updates)
		{
			update.Encode(messageData, ref currentPosition, domainNames);
		}

		foreach (DnsRecordBase record in AdditionalRecords)
		{
			record.Encode(messageData, ref currentPosition, domainNames);
		}
	}

	internal override bool ValidateResponse(DnsMessageBase responseBase)
	{
		DnsUpdateMessage? response = responseBase as DnsUpdateMessage;

		if (response == null)
			return false;

		if (TransactionID != response.TransactionID)
			return false;

		if ((response.ReturnCode == ReturnCode.NoError) || (response.ReturnCode == ReturnCode.NxDomain))
		{
			return response.ZoneName.Equals(ZoneName, false);
		}

		return true;
	}

	protected internal override void Add0x20Bits()
	{
		ZoneName = ZoneName.Add0x20Bits();
	}

	protected internal override void AddSubsequentResponse(DnsMessageBase respone)
	{
		throw new NotSupportedException();
	}

	protected internal override bool AllowMultipleResponses => false;

	protected internal override IEnumerable<DnsMessageBase> SplitResponse()
	{
		throw new NotSupportedException();
	}

	protected override void ParseRfc8427JsonAnswerSection(JsonElement json)
	{
		var sectionList = new List<PrequisiteBase>();

		foreach (var recordJson in json.EnumerateArray())
		{
			if (recordJson.TryGetProperty("rrSet", out var rrsetArrayJson))
			{
				foreach (var rrsetJson in rrsetArrayJson.EnumerateArray())
				{
					sectionList.Add(PrequisiteBase.ParseRfc8427Json(recordJson, rrsetJson));
				}
			}
			else
			{
				sectionList.Add(PrequisiteBase.ParseRfc8427Json(recordJson, recordJson));
			}
		}

		Prequisites = sectionList;
	}

	protected override void ParseRfc8427JsonAuthoritySection(JsonElement json)
	{
		var sectionList = new List<UpdateBase>();

		foreach (var recordJson in json.EnumerateArray())
		{
			if (recordJson.TryGetProperty("rrSet", out var rrsetArrayJson))
			{
				foreach (var rrsetJson in rrsetArrayJson.EnumerateArray())
				{
					sectionList.Add(UpdateBase.ParseRfc8427Json(recordJson, rrsetJson));
				}
			}
			else
			{
				sectionList.Add(UpdateBase.ParseRfc8427Json(recordJson, recordJson));
			}
		}

		Updates = sectionList;
	}

	protected override void WriteRfc8427JsonSections(Utf8JsonWriter writer, JsonSerializerOptions options)
	{
		writer.WriteNumber("QDCOUNT", 1);
		writer.WriteNumber("ANCOUNT", Prequisites.Count);
		writer.WriteNumber("NSCOUNT", Updates.Count);
		writer.WriteNumber("ARCOUNT", AdditionalRecords.Count);

		writer.WriteString("QNAME", ZoneName.ToString(true));
		writer.WriteNumber("QTYPE", (ushort) RecordType.Soa);
		writer.WriteString("QTYPEname", RecordType.Soa.ToShortString());
		writer.WriteNumber("QCLASS", (ushort) RecordClass.INet);
		writer.WriteString("QCLASSname", RecordClass.INet.ToShortString());

		WriteRfc8427PrequisiteSection(writer, options);
		WriteRfc8427UpdateSection(writer, options);
		WriteRfc8427JsonSection("additionalRRs", AdditionalRecords, writer, options);
	}

	private void WriteRfc8427PrequisiteSection(Utf8JsonWriter writer, JsonSerializerOptions options)
	{
		if (Prequisites.Count == 0)
			return;

		writer.WriteStartArray("answerRRs");

		foreach (var prequisite in Prequisites)
		{
			prequisite.WriteRfc8427Json(writer, options);
		}

		writer.WriteEndArray();
	}

	private void WriteRfc8427UpdateSection(Utf8JsonWriter writer, JsonSerializerOptions options)
	{
		if (Prequisites.Count == 0)
			return;

		writer.WriteStartArray("authorityRRs");

		foreach (var update in Updates)
		{
			update.WriteRfc8427Json(writer, options);
		}

		writer.WriteEndArray();
	}
}