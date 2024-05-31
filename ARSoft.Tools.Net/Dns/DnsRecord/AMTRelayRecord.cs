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
///   <para>Automatic Multicast Tunneling Relay</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc8777.html">RFC 8777</a>.
///   </para>
/// </summary>
// ReSharper disable once InconsistentNaming
public class AMTRelayRecord : DnsRecordBase
{
	public enum RelayFieldType : byte
	{
		/// <summary>
		///   <para>The relay field is empty.</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8777.html">RFC 8777</a>.
		///   </para>
		/// </summary>
		None = 0,

		/// <summary>
		///   <para>The relay field contains an IPv4 address.</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8777.html">RFC 8777</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		IPv4 = 1,

		/// <summary>
		///   <para>The relay field contains an IPv6 address.</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8777.html">RFC 8777</a>.
		///   </para>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		IPv6 = 2,

		/// <summary>
		///   <para>The relay field contains a domain name.</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8777.html">RFC 8777</a>.
		///   </para>
		/// </summary>
		DomainName = 3,
	}

	/// <summary>
	///   The precedence of the record
	/// </summary>
	public byte Precedence { get; }

	/// <summary>
	///   The Discovery Optional flag
	/// </summary>
	public bool IsDiscoveryOptional { get; }

	/// <summary>
	///   The type of the relay
	/// </summary>
	public RelayFieldType RelayType { get; }

	/// <summary>
	///   The relay
	/// </summary>
	public string Relay { get; }

	internal AMTRelayRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
		: base(name, recordType, recordClass, timeToLive)
	{
		Precedence = resultData[currentPosition++];
		var type = resultData[currentPosition++];
		IsDiscoveryOptional = type > 127;
		RelayType = (RelayFieldType) (type & 127);
		switch (RelayType)
		{
			case RelayFieldType.IPv4:
				Relay = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 4)).ToString();
				break;
			case RelayFieldType.IPv6:
				Relay = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 16)).ToString();
				break;
			case RelayFieldType.DomainName:
				Relay = DnsMessageBase.ParseDomainName(resultData, ref currentPosition).ToString(true);
				break;
			default:
				Relay = DomainName.Root.ToString(true);
				break;
		}
	}

	internal AMTRelayRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
		: base(name, recordType, recordClass, timeToLive)
	{
		if (stringRepresentation.Length != 4)
			throw new FormatException();

		Precedence = Byte.Parse(stringRepresentation[0]);
		switch (stringRepresentation[1])
		{
			case "0":
				IsDiscoveryOptional = false;
				break;
			case "1":
				IsDiscoveryOptional = true;
				break;
			default:
				throw new FormatException();
		}

		RelayType = (RelayFieldType) Byte.Parse(stringRepresentation[2]);
		switch (RelayType)
		{
			case RelayFieldType.IPv4:
			{
				if (IPAddress.TryParse(stringRepresentation[3], out var address) && address.AddressFamily == AddressFamily.InterNetwork)
				{
					Relay = address.ToString();
				}
				else
				{
					throw new FormatException();
				}

				break;
			}
			case RelayFieldType.IPv6:
			{
				if (IPAddress.TryParse(stringRepresentation[3], out var address) && address.AddressFamily == AddressFamily.InterNetworkV6)
				{
					Relay = address.ToString();
				}
				else
				{
					throw new FormatException();
				}

				break;
			}
			case RelayFieldType.DomainName:
				Relay = ParseDomainName(origin, stringRepresentation[3]).ToString(true);
				break;
			default:
				Relay = DomainName.Root.ToString(true);
				break;
		}
	}

	/// <summary>
	///   Creates a new instance of the AMTRelayRecord class
	/// </summary>
	/// <param name="name"> Name of the zone </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="precedence">The precedence of the record</param>
	public AMTRelayRecord(DomainName name, int timeToLive, byte precedence)
		: base(name, RecordType.AMTRelay, RecordClass.INet, timeToLive)
	{
		Precedence = precedence;
		IsDiscoveryOptional = false;
		RelayType = RelayFieldType.None;
		Relay = DomainName.Root.ToString(true);
	}

	/// <summary>
	///   Creates a new instance of the AMTRelayRecord class
	/// </summary>
	/// <param name="name"> Name of the zone </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="precedence">The precedence of the record</param>
	/// <param name="isDiscoveryOptional">The Discovery Optional flag</param>
	/// <param name="relayAddress">The address of the relay</param>
	public AMTRelayRecord(DomainName name, int timeToLive, byte precedence, bool isDiscoveryOptional, IPAddress relayAddress)
		: base(name, RecordType.AMTRelay, RecordClass.INet, timeToLive)
	{
		Precedence = precedence;
		IsDiscoveryOptional = isDiscoveryOptional;
		RelayType = relayAddress.AddressFamily == AddressFamily.InterNetwork ? RelayFieldType.IPv4 : RelayFieldType.IPv6;
		Relay = relayAddress.ToString();
	}

	/// <summary>
	///   Creates a new instance of the AMTRelayRecord class
	/// </summary>
	/// <param name="name"> Name of the zone </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="precedence">The precedence of the record</param>
	/// <param name="isDiscoveryOptional">The Discovery Optional flag</param>
	/// <param name="relayName">The domain name of the relay</param>
	public AMTRelayRecord(DomainName name, int timeToLive, byte precedence, bool isDiscoveryOptional, DomainName relayName)
		: base(name, RecordType.AMTRelay, RecordClass.INet, timeToLive)
	{
		Precedence = precedence;
		IsDiscoveryOptional = isDiscoveryOptional;
		RelayType = RelayFieldType.DomainName;
		Relay = relayName.ToString(true);
	}

	internal override string RecordDataToString()
	{
		return Precedence + " " + (IsDiscoveryOptional ? "1" : "0") + " " + (byte) RelayType + " " + Relay;
	}

	protected internal override int MaximumRecordDataLength
	{
		get
		{
			var res = 2;
			return RelayType switch
			{
				RelayFieldType.IPv4 => res + 4,
				RelayFieldType.IPv6 => res + 16,
				RelayFieldType.DomainName => res + 2 + Relay.Length,
				_ => res
			};
		}
	}

	protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
	{
		messageData[currentPosition++] = Precedence;
		messageData[currentPosition++] = (byte) ((byte) RelayType | (IsDiscoveryOptional ? 128 : 0));
		switch (RelayType)
		{
			case RelayFieldType.IPv4:
			case RelayFieldType.IPv6:
				byte[] addressBuffer = IPAddress.Parse(Relay).GetAddressBytes();
				DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, addressBuffer);
				break;
			case RelayFieldType.DomainName:
				DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, ParseDomainName(DomainName.Root, Relay), null, false);
				break;
		}
	}
}