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

using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>IPv6 hint service binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
// ReSharper disable once InconsistentNaming
internal class IPv6HintBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   IPv6 address hints
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public IPAddress[] IPv6Hints { get; }

	/// <summary>
	///   Creates a new instance of the IPv4HintBindingParameter class
	/// </summary>
	/// <param name="hints"> Address hints </param>
	public IPv6HintBindingParameter(IPAddress[] hints)
	{
		if (hints.Any(x => x.AddressFamily != AddressFamily.InterNetworkV6))
			throw new ArgumentOutOfRangeException(nameof(hints), "Only IPv6 addresses are allowed");

		IPv6Hints = hints;
	}

	internal IPv6HintBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		IPv6Hints = new IPAddress[valueLength / 16];
		for (int i = 0; i < IPv6Hints.Length; i++)
		{
			IPv6Hints[i] = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 16));
		}
	}

	internal IPv6HintBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (String.IsNullOrWhiteSpace(parameter))
			throw new FormatException();

		IPv6Hints = parameter.Split(',').Select(IPAddress.Parse).ToArray();

		if (IPv6Hints.Any(x => x.AddressFamily != AddressFamily.InterNetworkV6))
			throw new FormatException();
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.IPv6Hint;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		foreach (var hint in IPv6Hints)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, hint.GetAddressBytes(), 16);
		}
	}

	protected override int ValueDataLength => IPv6Hints.Length * 16;

	protected override string ValueToString()
	{
		return String.Join<IPAddress>(',', IPv6Hints);
	}
}