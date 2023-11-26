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
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Security Key</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc4034.html">RFC 4034</a>
	///     ,
	///     <a href="https://www.rfc-editor.org/rfc/rfc3755.html">RFC 3755</a>
	///     ,
	///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>
	///     and
	///     <a href="https://www.rfc-editor.org/rfc/rfc2930.html">RFC 2930</a>.
	///   </para>
	/// </summary>
	public abstract class KeyRecordBase : DnsRecordBase
	{
		/// <summary>
		///   Type of key
		/// </summary>
		[Flags]
		public enum KeyTypeFlag : ushort
		{
			/// <summary>
			///   <para>Use of the key is prohibited for authentication</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			AuthenticationProhibited = 0x8000,

			/// <summary>
			///   <para>Use of the key is prohibited for confidentiality</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			ConfidentialityProhibited = 0x4000,

			/// <summary>
			///   <para>Use of the key for authentication and/or confidentiality is permitted</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			BothProhibited = 0x0000,

			/// <summary>
			///   <para>There is no key information</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			NoKey = 0xc000,
		}

		/// <summary>
		///   Type of name
		/// </summary>
		public enum NameTypeFlag : ushort
		{
			/// <summary>
			///   <para>Key is associated with a user or account</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			User = 0x0000,

			/// <summary>
			///   <para>Key is associated with a zone</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			Zone = 0x0100,

			/// <summary>
			///   <para>Key is associated with a host</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			Host = 0x0200,

			/// <summary>
			///   <para>Reserved</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			Reserved = 0x0300,
		}

		/// <summary>
		///   Protocol for which the key is used
		/// </summary>
		public enum ProtocolType : byte
		{
			/// <summary>
			///   <para>Use in connection with TLS</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			Tls = 1,

			/// <summary>
			///   <para>Use in connection with email</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			Email = 2,

			/// <summary>
			///   <para>Used for DNS security</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			DnsSec = 3,

			/// <summary>
			///   <para>Refer to the Oakley/IPSEC  protocol</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			IpSec = 4,

			/// <summary>
			///   <para>Used in connection with any protocol</para>
			///   <para>
			///     Defined in
			///     <a href="https://www.rfc-editor.org/rfc/rfc2535.html">RFC 2535</a>.
			///   </para>
			/// </summary>
			Any = 255,
		}

		/// <summary>
		///   Flags of the key
		/// </summary>
		public ushort Flags { get; private set; }

		/// <summary>
		///   Protocol for which the key is used
		/// </summary>
		public ProtocolType Protocol { get; private set; }

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public DnsSecAlgorithm Algorithm { get; private set; }

		#region Flags
		/// <summary>
		///   Type of key
		/// </summary>
		public KeyTypeFlag Type
		{
			get { return (KeyTypeFlag) (Flags & 0xc000); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0x3fff);
				Flags = (ushort) (clearedOp | (ushort) value);
			}
		}

		/// <summary>
		///   True, if a second flag field should be added
		/// </summary>
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

		/// <summary>
		///   Type of name
		/// </summary>
		public NameTypeFlag NameType
		{
			get { return (NameTypeFlag) (Flags & 0x0300); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0xfcff);
				Flags = (ushort) (clearedOp | (ushort) value);
			}
		}

		/// <summary>
		///   Is the key authorized for zone updates
		/// </summary>
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

		/// <summary>
		///   Is the key authorized for updates of records signed with other key
		/// </summary>
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

		/// <summary>
		///   Is the key only authorized for update of records with the same record name as the key
		/// </summary>
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

		/// <summary>
		///   Is the key an update key
		/// </summary>
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

		protected KeyRecordBase(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Flags = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Protocol = (ProtocolType) resultData[currentPosition++];
			Algorithm = (DnsSecAlgorithm) resultData[currentPosition++];
		}

		protected KeyRecordBase(DomainName name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, DnsSecAlgorithm algorithm)
			: base(name, RecordType.Key, recordClass, timeToLive)
		{
			Flags = flags;
			Protocol = protocol;
			Algorithm = algorithm;
		}

		protected KeyRecordBase(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length < 4)
				throw new FormatException();

			Flags = UInt16.Parse(stringRepresentation[0]);
			Protocol = (ProtocolType) Byte.Parse(stringRepresentation[1]);
			Algorithm = (DnsSecAlgorithm) Byte.Parse(stringRepresentation[2]);
		}

		internal sealed override string RecordDataToString()
		{
			return Flags
			       + " " + (byte) Protocol
			       + " " + (byte) Algorithm
			       + " " + PublicKeyToString();
		}

		protected abstract string PublicKeyToString();

		protected internal sealed override int MaximumRecordDataLength => 4 + MaximumPublicKeyLength;

		protected abstract int MaximumPublicKeyLength { get; }

		protected internal sealed override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Flags);
			messageData[currentPosition++] = (byte) Protocol;
			messageData[currentPosition++] = (byte) Algorithm;
			EncodePublicKey(messageData, ref currentPosition, domainNames);
		}

		protected abstract void EncodePublicKey(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames);
	}
}