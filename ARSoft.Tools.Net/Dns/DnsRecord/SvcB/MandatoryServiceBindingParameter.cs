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

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>Mandatory keys service binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
public class MandatoryServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   Mandatory keys
	/// </summary>
	public ServiceBindingParameterKey[] Keys { get; }

	/// <summary>
	///   Creates a new instance of the PortServiceBindingParameter class
	/// </summary>
	/// <param name="keys"> Mandatory keys </param>
	public MandatoryServiceBindingParameter(ServiceBindingParameterKey[] keys)
	{
		Keys = keys;
	}

	internal MandatoryServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		Keys = new ServiceBindingParameterKey[valueLength / 2];
		for (int i = 0; i < Keys.Length; i++)
		{
			Keys[i] = (ServiceBindingParameterKey) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
		}
	}

	internal MandatoryServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (String.IsNullOrWhiteSpace(parameter))
			throw new FormatException();

		Keys = parameter.Split(',').Select(ServiceBindingParameterKeyHelper.Parse).ToArray();
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.Mandatory;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		foreach (var type in Keys.OrderBy(t => t))
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) type);
		}
	}

	protected override int ValueDataLength => Keys.Length * 2;

	protected override string ValueToString()
	{
		return String.Join(',', Keys.Select(ServiceBindingParameterKeyHelper.ToString));
	}
}