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

using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>IPv4 hint service binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
// ReSharper disable once InconsistentNaming
internal class IPv4HintBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   IPv4 address hints
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public IPAddress[] IPv4Hints { get; }

	/// <summary>
	///   Creates a new instance of the IPv4HintBindingParameter class
	/// </summary>
	/// <param name="hints"> Address hints </param>
	public IPv4HintBindingParameter(IPAddress[] hints)
	{
		if (hints.Any(x => x.AddressFamily != AddressFamily.InterNetwork))
			throw new ArgumentOutOfRangeException(nameof(hints), "Only IPv4 addresses are allowed");

		IPv4Hints = hints;
	}

	internal IPv4HintBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		IPv4Hints = new IPAddress[valueLength / 4];
		for (int i = 0; i < IPv4Hints.Length; i++)
		{
			IPv4Hints[i] = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 4));
		}
	}

	internal IPv4HintBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (String.IsNullOrWhiteSpace(parameter))
			throw new FormatException();

		IPv4Hints = parameter.Split(',').Select(IPAddress.Parse).ToArray();

		if (IPv4Hints.Any(x => x.AddressFamily != AddressFamily.InterNetwork))
			throw new FormatException();
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.IPv4Hint;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		foreach (var hint in IPv4Hints)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, hint.GetAddressBytes(), 4);
		}
	}

	protected override int ValueDataLength => IPv4Hints.Length * 4;

	protected override string ValueToString()
	{
		return String.Join<IPAddress>(',', IPv4Hints);
	}
}