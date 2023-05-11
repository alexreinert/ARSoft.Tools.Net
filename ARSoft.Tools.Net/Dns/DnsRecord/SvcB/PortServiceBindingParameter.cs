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
///   <para>Port service binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
public class PortServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   Port for alternative endpoint
	/// </summary>
	public ushort Port { get; }

	/// <summary>
	///   Creates a new instance of the PortServiceBindingParameter class
	/// </summary>
	/// <param name="port"> Port for alternative endpoint </param>
	public PortServiceBindingParameter(ushort port)
	{
		Port = port;
	}

	internal PortServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		Port = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
	}

	internal PortServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (!UInt16.TryParse(parameter, out var port))
			throw new FormatException();

		Port = port;
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.Port;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Port);
	}

	protected override int ValueDataLength => 2;

	protected override string ValueToString()
	{
		return Port.ToString();
	}
}