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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>IPsec key storage</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
	///   </para>
	/// </summary>
	public class IpSecKeyRecord : DnsRecordBase
	{
		/// <summary>
		///   Algorithm of key
		/// </summary>
		public enum IpSecAlgorithm : byte
		{
			/// <summary>
			///   None
			/// </summary>
			None = 0,

			/// <summary>
			///   <para>RSA</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
			///   </para>
			/// </summary>
			Rsa = 1,

			/// <summary>
			///   <para>DSA</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
			///   </para>
			/// </summary>
			Dsa = 2,

			/// <summary>
			///   <para>ECDSA</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc8005.html">RFC 8005</a>.
			///   </para>
			/// </summary>
			EcDsa = 3,

			/// <summary>
			///   <para>EdDSA</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc9373.html">RFC 9373</a>.
			///   </para>
			/// </summary>
			EdDsa = 4,
		}

		/// <summary>
		///   Type of gateway
		/// </summary>
		public enum IpSecGatewayType : byte
		{
			/// <summary>
			///   None
			/// </summary>
			None = 0,

			/// <summary>
			///   <para>Gateway is a IPv4 address</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
			///   </para>
			/// </summary>
			IpV4 = 1,

			/// <summary>
			///   <para>Gateway is a IPv6 address</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
			///   </para>
			/// </summary>
			IpV6 = 2,

			/// <summary>
			///   <para>Gateway is a domain name</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc4025.html">RFC 4025</a>.
			///   </para>
			/// </summary>
			Domain = 3,
		}

		/// <summary>
		///   Precedence of the record
		/// </summary>
		public byte Precedence { get; }

		/// <summary>
		///   Type of gateway
		/// </summary>
		public IpSecGatewayType GatewayType { get; }

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public IpSecAlgorithm Algorithm { get; }

		/// <summary>
		///   Address of the gateway
		/// </summary>
		public string Gateway { get; }

		/// <summary>
		///   Binary data of the public key
		/// </summary>
		public byte[] PublicKey { get; }

		internal IpSecKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			int startPosition = currentPosition;

			Precedence = resultData[currentPosition++];
			GatewayType = (IpSecGatewayType) resultData[currentPosition++];
			Algorithm = (IpSecAlgorithm) resultData[currentPosition++];
			switch (GatewayType)
			{
				case IpSecGatewayType.IpV4:
					Gateway = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 4)).ToString();
					break;
				case IpSecGatewayType.IpV6:
					Gateway = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 16)).ToString();
					break;
				case IpSecGatewayType.Domain:
					Gateway = DnsMessageBase.ParseDomainName(resultData, ref currentPosition).ToString(true);
					break;
				default:
					Gateway = String.Empty;
					break;
			}

			PublicKey = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length + startPosition - currentPosition);
		}

		internal IpSecKeyRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length < 5)
				throw new FormatException();

			Precedence = Byte.Parse(stringRepresentation[0]);
			GatewayType = (IpSecGatewayType) Byte.Parse(stringRepresentation[1]);
			Algorithm = (IpSecAlgorithm) Byte.Parse(stringRepresentation[2]);
			switch (GatewayType)
			{
				case IpSecGatewayType.IpV4:
				{
					if (IPAddress.TryParse(stringRepresentation[3], out var address) && address.AddressFamily == AddressFamily.InterNetwork)
					{
						Gateway = address.ToString();
					}
					else
					{
						throw new FormatException();
					}

					break;
				}
				case IpSecGatewayType.IpV6:
				{
					if (IPAddress.TryParse(stringRepresentation[3], out var address) && address.AddressFamily == AddressFamily.InterNetworkV6)
					{
						Gateway = address.ToString();
					}
					else
					{
						throw new FormatException();
					}

					break;
				}
				case IpSecGatewayType.Domain:
					Gateway = ParseDomainName(origin, stringRepresentation[3]).ToString(true);
					break;
				default:
					Gateway = DomainName.Root.ToString(true);
					break;
			}

			PublicKey = String.Join(String.Empty, stringRepresentation.Skip(4)).FromBase64String();
		}

		/// <summary>
		///   Creates a new instance of the IpSecKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="precedence"> Precedence of the record </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="gateway"> Address of the gateway </param>
		/// <param name="publicKey"> Binary data of the public key </param>
		public IpSecKeyRecord(DomainName name, int timeToLive, byte precedence, IpSecAlgorithm algorithm, DomainName gateway, byte[] publicKey)
			: base(name, RecordType.IpSecKey, RecordClass.INet, timeToLive)
		{
			Precedence = precedence;
			GatewayType = IpSecGatewayType.Domain;
			Algorithm = algorithm;
			Gateway = gateway.ToString(true);
			PublicKey = publicKey;
		}

		/// <summary>
		///   Creates a new instance of the IpSecKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="precedence"> Precedence of the record </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="gateway"> Address of the gateway </param>
		/// <param name="publicKey"> Binary data of the public key </param>
		public IpSecKeyRecord(DomainName name, int timeToLive, byte precedence, IpSecAlgorithm algorithm, IPAddress gateway, byte[] publicKey)
			: base(name, RecordType.IpSecKey, RecordClass.INet, timeToLive)
		{
			Precedence = precedence;
			GatewayType = (gateway.AddressFamily == AddressFamily.InterNetwork) ? IpSecGatewayType.IpV4 : IpSecGatewayType.IpV6;
			Algorithm = algorithm;
			Gateway = gateway.ToString();
			PublicKey = publicKey;
		}

		internal override string RecordDataToString()
		{
			return Precedence
			       + " " + (byte) GatewayType
			       + " " + (byte) Algorithm
			       + " " + Gateway
			       + " " + PublicKey.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get
			{
				int res = 3;
				switch (GatewayType)
				{
					case IpSecGatewayType.IpV4:
						res += 4;
						break;
					case IpSecGatewayType.IpV6:
						res += 16;
						break;
					case IpSecGatewayType.Domain:
						res += 2 + Gateway.Length;
						break;
				}

				res += PublicKey.Length;
				return res;
			}
		}

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			messageData[currentPosition++] = Precedence;
			messageData[currentPosition++] = (byte) GatewayType;
			messageData[currentPosition++] = (byte) Algorithm;
			switch (GatewayType)
			{
				case IpSecGatewayType.IpV4:
				case IpSecGatewayType.IpV6:
					byte[] addressBuffer = IPAddress.Parse(Gateway).GetAddressBytes();
					DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, addressBuffer);
					break;
				case IpSecGatewayType.Domain:
					DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, ParseDomainName(DomainName.Root, Gateway), null, false);
					break;
			}

			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}