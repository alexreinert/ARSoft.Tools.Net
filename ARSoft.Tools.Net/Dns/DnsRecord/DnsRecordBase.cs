#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Base class representing a dns record
	/// </summary>
	public abstract class DnsRecordBase : DnsMessageEntryBase, IComparable<DnsRecordBase>, IEquatable<DnsRecordBase>
	{
		internal ushort RecordDataLength { get; set; }

		/// <summary>
		///   Seconds which a record should be cached at most
		/// </summary>
		public int TimeToLive { get; internal set; }

		protected DnsRecordBase(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive)
			: base(name, recordType, recordClass)
		{
			TimeToLive = timeToLive;
		}

		#region ToString
		internal abstract string RecordDataToString();

		/// <summary>
		///   Returns the textual representation of a record
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			string recordData = RecordDataToString();
			return Name + " " + TimeToLive + " " + RecordClass.ToShortString() + " " + RecordType.ToShortString() + (String.IsNullOrEmpty(recordData) ? "" : " " + recordData);
		}
		#endregion

		#region Parsing
		internal static DnsRecordBase ParseRecordFromMessage(byte[] resultData, ref int currentPosition)
		{
			int startPosition = currentPosition;
			DomainName name = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
			RecordType recordType = (RecordType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);

			RecordClass recordClass = (RecordClass) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int timeToLive = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			ushort recordDataLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int recordDataPosition = currentPosition;
			currentPosition += recordDataLength;

			return ParseRecordFromBinary(startPosition, name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
		}

		internal static DnsRecordBase ParseRecordFromBinary(int recordStartPosition, DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, byte[] resultData, int recordDataPosition, int recordDataLength)
		{
			switch (recordType)
			{
				case RecordType.A:
					return new ARecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Ns:
					return new NsRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.CName:
					return new CNameRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Soa:
					return new SoaRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Wks:
					return new WksRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Ptr:
					return new PtrRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.HInfo:
					return new HInfoRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Mx:
					return new MxRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Txt:
					return new TxtRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Rp:
					return new RpRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Afsdb:
					return new AfsdbRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.X25:
					return new X25Record(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Isdn:
					return new IsdnRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Rt:
					return new RtRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Nsap:
					return new NsapRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Sig:
					return new SigRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Key:
#pragma warning disable 0612
					if ((recordType == RecordType.Key) && (resultData[recordDataPosition + 3] == (byte) DnsSecAlgorithm.DiffieHellman))
#pragma warning restore 0612
					{
						return new DiffieHellmanKeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
					}
					else
					{
						return new KeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
					}
				case RecordType.Px:
					return new PxRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.GPos:
					return new GPosRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Aaaa:
					return new AaaaRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Loc:
					return new LocRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Srv:
					return new SrvRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Naptr:
					return new NaptrRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Kx:
					return new KxRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Cert:
					return new CertRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.DName:
					return new DNameRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Opt:
					return new OptRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Apl:
					return new AplRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Ds:
					return new DsRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.SshFp:
					return new SshFpRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.IpSecKey:
					return new IpSecKeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.RrSig:
					return new RrSigRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.NSec:
					return new NSecRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.DnsKey:
					return new DnsKeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Dhcid:
					return new DhcidRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.NSec3:
					return new NSec3Record(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.NSec3Param:
					return new NSec3ParamRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Tlsa:
					return new TlsaRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Hip:
					return new HipRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.CDs:
					return new CDsRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.CDnsKey:
					return new CDnsKeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.OpenPGPKey:
					return new OpenPGPKeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.CSync:
					return new CSyncRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
#pragma warning disable 0612
				case RecordType.Spf:
					return new SpfRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
#pragma warning restore 0612
				case RecordType.NId:
					return new NIdRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.L32:
					return new L32Record(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.L64:
					return new L64Record(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.LP:
					return new LPRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Eui48:
					return new Eui48Record(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Eui64:
					return new Eui64Record(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.TKey:
					return new TKeyRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.TSig:
					return new TSigRecord(recordStartPosition, name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Uri:
					return new UriRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.CAA:
					return new CAARecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				case RecordType.Dlv:
					return new DlvRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);

				default:
					return new UnknownRecord(name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
			}
		}

		internal static DnsRecordBase ParseFromStringRepresentation(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
		{
			if ((stringRepresentation.Length > 0) && (stringRepresentation[0] == @"\#"))
			{
				if (stringRepresentation.Length < 2)
					throw new FormatException();

				if (stringRepresentation[0] != @"\#")
					throw new FormatException();

				int length = Int32.Parse(stringRepresentation[1]);

				byte[] byteData = String.Join("", stringRepresentation.Skip(2)).FromBase16String();

				if (length != byteData.Length)
					throw new FormatException();

				return ParseRecordFromBinary(0, name, recordType, recordClass, timeToLive, byteData, 0, length);
			}
			else
			{
				switch (recordType)
				{
					case RecordType.A:
						return new ARecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Ns:
						return new NsRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.CName:
						return new CNameRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Soa:
						return new SoaRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Wks:
						return new WksRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Ptr:
						return new PtrRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.HInfo:
						return new HInfoRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Mx:
						return new MxRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Txt:
						return new TxtRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Rp:
						return new RpRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Afsdb:
						return new AfsdbRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.X25:
						return new X25Record(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Isdn:
						return new IsdnRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Rt:
						return new RtRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Nsap:
						return new NsapRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Sig:
						return new SigRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Key:
						return new KeyRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Px:
						return new PxRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.GPos:
						return new GPosRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Aaaa:
						return new AaaaRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Loc:
						return new LocRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Srv:
						return new SrvRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Naptr:
						return new NaptrRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Kx:
						return new KxRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Cert:
						return new CertRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.DName:
						return new DNameRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Opt:
						return new OptRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Apl:
						return new AplRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Ds:
						return new DsRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.SshFp:
						return new SshFpRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.IpSecKey:
						return new IpSecKeyRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.RrSig:
						return new RrSigRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.NSec:
						return new NSecRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.DnsKey:
						return new DnsKeyRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Dhcid:
						return new DhcidRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.NSec3:
						return new NSec3Record(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.NSec3Param:
						return new NSec3ParamRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Tlsa:
						return new TlsaRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Hip:
						return new HipRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.CDs:
						return new CDsRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.CDnsKey:
						return new CDnsKeyRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.OpenPGPKey:
						return new OpenPGPKeyRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.CSync:
						return new CSyncRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
#pragma warning disable 0612
					case RecordType.Spf:
						return new SpfRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
#pragma warning restore 0612
					case RecordType.NId:
						return new NIdRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.L32:
						return new L32Record(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.L64:
						return new L64Record(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.LP:
						return new LPRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Eui48:
						return new Eui48Record(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Eui64:
						return new Eui64Record(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.TKey:
						return new TKeyRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.TSig:
						return new TSigRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Uri:
						return new UriRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.CAA:
						return new CAARecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
					case RecordType.Dlv:
						return new DlvRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);

					default:
						return new UnknownRecord(name, recordType, recordClass, timeToLive, origin, stringRepresentation);
				}
			}
		}

		protected DomainName ParseDomainName(DomainName origin, string name)
		{
			if (String.IsNullOrEmpty(name))
				throw new ArgumentException("Name must be provided", nameof(name));

			if (name.EndsWith("."))
				return DomainName.ParseFromMasterfile(name);

			return DomainName.ParseFromMasterfile(name) + origin;
		}
		#endregion

		#region Encoding
		internal override sealed int MaximumLength => Name.MaximumRecordDataLength + 12 + MaximumRecordDataLength;

		internal void Encode(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical = false)
		{
			EncodeRecordHeader(messageData, offset, ref currentPosition, domainNames, useCanonical);
			EncodeRecordBody(messageData, offset, ref currentPosition, domainNames, useCanonical);
		}

		internal void EncodeRecordHeader(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Name, domainNames, useCanonical);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordType);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordClass);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, TimeToLive);
		}

		internal void EncodeRecordBody(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			int recordDataOffset = currentPosition + 2;
			EncodeRecordData(messageData, offset, ref recordDataOffset, domainNames, useCanonical);
			EncodeRecordLength(messageData, offset, ref currentPosition, recordDataOffset);
		}

		internal void EncodeRecordLength(byte[] messageData, int offset, ref int recordDataOffset, int recordPosition)
		{
			DnsMessageBase.EncodeUShort(messageData, ref recordDataOffset, (ushort) (recordPosition - recordDataOffset - 2));
			recordDataOffset = recordPosition;
		}

		protected internal abstract int MaximumRecordDataLength { get; }

		protected internal abstract void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical);
		#endregion

		internal T Clone<T>()
			where T : DnsRecordBase
		{
			return (T) MemberwiseClone();
		}

		public int CompareTo(DnsRecordBase? other)
		{
			if (other == null)
				return 1;

			int compare = Name.CompareTo(other.Name);
			if (compare != 0)
				return compare;

			compare = RecordType.CompareTo(other.RecordType);
			if (compare != 0)
				return compare;

			compare = RecordClass.CompareTo(other.RecordClass);
			if (compare != 0)
				return compare;

			compare = TimeToLive.CompareTo(other.TimeToLive);
			if (compare != 0)
				return compare;

			byte[] thisBuffer = new byte[MaximumRecordDataLength];
			int thisLength = 0;
			EncodeRecordData(thisBuffer, 0, ref thisLength, null, false);

			byte[] otherBuffer = new byte[other.MaximumRecordDataLength];
			int otherLength = 0;
			other.EncodeRecordData(otherBuffer, 0, ref otherLength, null, false);

			for (int i = 0; i < Math.Min(thisLength, otherLength); i++)
			{
				compare = thisBuffer[i].CompareTo(otherBuffer[i]);
				if (compare != 0)
					return compare;
			}

			return thisLength.CompareTo(otherLength);
		}

		private int? _hashCode;

		[SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
		public override int GetHashCode()
		{
			if (!_hashCode.HasValue)
			{
				_hashCode = ToString().GetHashCode();
			}

			return _hashCode.Value;
		}

		public override bool Equals(object? obj)
		{
			return Equals(obj as DnsRecordBase);
		}

		public bool Equals(DnsRecordBase? other)
		{
			if (other == null)
				return false;

			return base.Equals(other)
			       && RecordDataToString().Equals(other.RecordDataToString());
		}
	}
}