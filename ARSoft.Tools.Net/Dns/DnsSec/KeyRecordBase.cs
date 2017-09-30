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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class KeyRecordBase : DnsRecordBase
	{
		public enum KeyTypeFlag : ushort
		{
			AuthenticationProhibited = 0x8000,
			ConfidentialityProhibited = 0x4000,
			BothProhibited = 0x0000,
			NoKey = 0xc000,
		}

		public enum NameTypeFlag : ushort
		{
			User = 0x0000,
			Zone = 0x0100,
			Host = 0x0200,
			Reserved = 0x0300,
		}

		public enum ProtocolType : byte
		{
			Tls = 1, // RFC2535
			Email = 2, // RFC2535
			DnsSec = 3, // RFC2535
			IpSec = 4, // RFC2535
			Any = 255, // RFC2535
		}

		public ushort Flags { get; private set; }
		public ProtocolType Protocol { get; private set; }
		public DnsSecAlgorithm Algorithm { get; private set; }

		#region Flags
		public KeyTypeFlag Type
		{
			get { return (KeyTypeFlag) (Flags & 0xc000); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0x3fff);
				Flags = (ushort) (clearedOp | (ushort) value);
			}
		}

		public bool IsExtendedFlag
		{
			get { return (Flags & 0x1000) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x1000;
				}
				else
				{
					Flags &= 0xefff;
				}
			}
		}

		public NameTypeFlag NameType
		{
			get { return (NameTypeFlag) (Flags & 0x0300); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0xfcff);
				Flags = (ushort) (clearedOp | (ushort) value);
			}
		}

		public bool IsZoneSignatory
		{
			get { return (Flags & 0x0008) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0008;
				}
				else
				{
					Flags &= 0xfff7;
				}
			}
		}

		public bool IsStrongSignatory
		{
			get { return (Flags & 0x0004) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0004;
				}
				else
				{
					Flags &= 0xfffb;
				}
			}
		}

		public bool IsUniqueSignatory
		{
			get { return (Flags & 0x0002) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0002;
				}
				else
				{
					Flags &= 0xfffd;
				}
			}
		}

		public bool IsGeneralSignatory
		{
			get { return (Flags & 0x0001) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0001;
				}
				else
				{
					Flags &= 0xfffe;
				}
			}
		}
		#endregion

		protected KeyRecordBase() {}

		protected KeyRecordBase(string name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, DnsSecAlgorithm algorithm)
			: base(name, RecordType.Key, recordClass, timeToLive)
		{
			Flags = flags;
			Protocol = protocol;
			Algorithm = algorithm;
		}

		internal override sealed void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Flags = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Protocol = (ProtocolType) resultData[startPosition++];
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			ParsePublicKey(resultData, startPosition, length - 4);
		}

		protected abstract void ParsePublicKey(byte[] resultData, int startPosition, int length);

		internal override sealed string RecordDataToString()
		{
			return Flags
			       + " " + (byte) Protocol
			       + " " + (byte) Algorithm
			       + " " + PublicKeyToString();
		}

		protected abstract string PublicKeyToString();

		protected internal override sealed int MaximumRecordDataLength
		{
			get { return 4 + MaximumPublicKeyLength; }
		}

		protected abstract int MaximumPublicKeyLength { get; }

		protected internal override sealed void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Flags);
			messageData[currentPosition++] = (byte) Protocol;
			messageData[currentPosition++] = (byte) Algorithm;
			EncodePublicKey(messageData, offset, ref currentPosition, domainNames);
		}

		protected abstract void EncodePublicKey(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames);
	}
}