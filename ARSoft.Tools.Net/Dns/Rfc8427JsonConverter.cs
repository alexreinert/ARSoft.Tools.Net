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

using System.Text.Json;
using System.Text.Json.Serialization;
using ARSoft.Tools.Net.Dns.DynamicUpdate;

namespace ARSoft.Tools.Net.Dns;

public class Rfc8427JsonConverter<T> : JsonConverter<T>
	where T : DnsMessageBase
{
	public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		var json = JsonElement.ParseValue(ref reader);

		switch (typeToConvert.Name)
		{
			case nameof(DnsMessage):
			case nameof(DnsRecordMessageBase):
				return DnsMessageBase.ParseRfc8427Json<DnsMessage>(json) as T;
			case nameof(DnsMessageBase):
				if (json.TryGetProperty("Opcode", out var opcodeJson) && opcodeJson.GetUInt16() == (ushort) OperationCode.Update)
				{
					return DnsMessageBase.ParseRfc8427Json<DnsUpdateMessage>(json) as T;
				}
				else
				{
					return DnsMessageBase.ParseRfc8427Json<DnsMessage>(json) as T;
				}
			case nameof(DnsUpdateMessage):
				return DnsMessageBase.ParseRfc8427Json<DnsUpdateMessage>(json) as T;
			case nameof(LlmnrMessage):
				return DnsMessageBase.ParseRfc8427Json<LlmnrMessage>(json) as T;
			case nameof(MulticastDnsMessage):
				return DnsMessageBase.ParseRfc8427Json<MulticastDnsMessage>(json) as T;
			default:
				throw new NotSupportedException("Unsupported dns message type");
		}
	}

	public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
	{
		value.WriteRfc8427Json(writer, options);
	}
}