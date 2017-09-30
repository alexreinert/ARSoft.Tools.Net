#region Copyright and License
// Copyright 2010..11 Alexander Reinert
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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class IpSecKeyRecord : DnsRecordBase
	{
		public enum IpSecAlgorithm : byte
		{
			None = 0,
			Rsa = 1, // RFC4025
			Dsa = 2, // RFC4025
		}

		public enum IpSecGatewayType : byte
		{
			None = 0,
			IpV4 = 1, // RFC4025
			IpV6 = 2, // RFC4025
			Domain = 3, // RFC4025
		}

		public byte Precedence { get; private set; }
		public IpSecGatewayType GatewayType { get; private set; }
		public IpSecAlgorithm Algorithm { get; private set; }
		public string Gateway { get; private set; }
		public byte[] PublicKey { get; private set; }

		internal IpSecKeyRecord() {}

		public IpSecKeyRecord(string name, int timeToLive, byte precedence, IpSecGatewayType gatewayType, IpSecAlgorithm algorithm, string gateway, byte[] publicKey)
			: base(name, RecordType.IpSecKey, RecordClass.INet, timeToLive)
		{
			Precedence = precedence;
			GatewayType = gatewayType;
			Algorithm = algorithm;
			Gateway = gateway ?? String.Empty;
			PublicKey = publicKey ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int startPosition = currentPosition;

			Precedence = resultData[currentPosition++];
			GatewayType = (IpSecGatewayType) resultData[currentPosition++];
			Algorithm = (IpSecAlgorithm) resultData[currentPosition++];
			switch (GatewayType)
			{
				case IpSecGatewayType.None:
					Gateway = String.Empty;
					break;
				case IpSecGatewayType.IpV4:
					Gateway = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 4)).ToString();
					break;
				case IpSecGatewayType.IpV6:
					Gateway = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 16)).ToString();
					break;
				case IpSecGatewayType.Domain:
					Gateway = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
					break;
			}
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length + startPosition - currentPosition);
		}

		internal override string RecordDataToString()
		{
			return Precedence
			       + " " + (byte) GatewayType
			       + " " + (byte) Algorithm
			       + " " + ((GatewayType == IpSecGatewayType.None) ? "." : Gateway)
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

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
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
					DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Gateway, false, domainNames);
					break;
			}
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}