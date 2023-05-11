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

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>Unknown protocol binding parameter</para>
/// </summary>
public class UnknownServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   Byte data of the parameter value
	/// </summary>
	public byte[] ValueData { get; }

	/// <summary>
	///   Creates a new instance of the UnknownServiceBindingParameter class
	/// </summary>
	/// <param name="key">Key of the service binding parameter</param>
	public UnknownServiceBindingParameter(ServiceBindingParameterKey key)
	{
		Key = key;
		ValueData = Array.Empty<byte>();
	}

	/// <summary>
	///   Creates a new instance of the UnknownServiceBindingParameter class
	/// </summary>
	/// <param name="key">Key of the service binding parameter</param>
	/// <param name="valueData">Byte data of the parameter value</param>
	public UnknownServiceBindingParameter(ServiceBindingParameterKey key, byte[] valueData)
	{
		Key = key;
		ValueData = valueData;
	}

	internal UnknownServiceBindingParameter(ServiceBindingParameterKey type, IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		Key = type;
		ValueData = DnsMessageBase.ParseByteData(resultData, ref currentPosition, valueLength);
	}

	internal UnknownServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		Key = type;
		ValueData = parameter == null ? Array.Empty<byte>() : parameter.Select(c => (byte) c).ToArray();
	}

	public override ServiceBindingParameterKey Key { get; }

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, ValueData);
	}

	protected override int ValueDataLength => ValueData.Length;

	protected override string ValueToString()
	{
		return "\"" + new String(ValueData.Select(b => (char) b).ToArray()).ToMasterfileLabelRepresentation() + "\"";
	}
}