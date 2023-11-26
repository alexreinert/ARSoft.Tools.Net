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
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Hashed next owner
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>.
	///   </para>
	/// </summary>
	public class NSec3Record : DnsRecordBase
	{
		/// <summary>
		///   Algorithm of hash
		/// </summary>
		public NSec3HashAlgorithm HashAlgorithm { get; private set; }

		/// <summary>
		///   Flags of the record
		/// </summary>
		public NSec3Flags Flags { get; private set; }

		/// <summary>
		///   Number of iterations
		/// </summary>
		public ushort Iterations { get; private set; }

		/// <summary>
		///   Binary data of salt
		/// </summary>
		public byte[] Salt { get; private set; }

		/// <summary>
		///   Binary data of hash of next owner
		/// </summary>
		public byte[] NextHashedOwner { get; internal set; }

		/// <summary>
		///   Types of next owner
		/// </summary>
		public List<RecordType> Types { get; private set; }

		internal DomainName NextHashedOwnerName => new(NextHashedOwner.ToBase32HexString(), this.Name.GetParentName());

		internal NSec3Record(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			int endPosition = currentPosition + length;

			HashAlgorithm = (NSec3HashAlgorithm) resultData[currentPosition++];
			Flags = (NSec3Flags) resultData[currentPosition++];
			Iterations = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int saltLength = resultData[currentPosition++];
			Salt = DnsMessageBase.ParseByteData(resultData, ref currentPosition, saltLength);
			int hashLength = resultData[currentPosition++];
			NextHashedOwner = DnsMessageBase.ParseByteData(resultData, ref currentPosition, hashLength);
			Types = NSecRecord.ParseTypeBitMap(resultData, ref currentPosition, endPosition);
		}

		internal NSec3Record(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length < 5)
				throw new FormatException();

			HashAlgorithm = (NSec3HashAlgorithm) Byte.Parse(stringRepresentation[0]);
			Flags = (NSec3Flags) Byte.Parse(stringRepresentation[1]);
			Iterations = UInt16.Parse(stringRepresentation[2]);
			Salt = (stringRepresentation[3] == "-") ? new byte[] { } : stringRepresentation[3].FromBase16String();
			NextHashedOwner = stringRepresentation[4].FromBase32HexString();
			Types = stringRepresentation.Skip(5).Select(RecordTypeHelper.ParseShortString).ToList();
		}

		/// <summary>
		///   Creates of new instance of the NSec3Record class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="hashAlgorithm"> Algorithm of hash </param>
		/// <param name="flags"> Flags of the record </param>
		/// <param name="iterations"> Number of iterations </param>
		/// <param name="salt"> Binary data of salt </param>
		/// <param name="nextHashedOwner"> Binary data of hash of next owner </param>
		/// <param name="types"> Types of next owner </param>
		public NSec3Record(DomainName name, RecordClass recordClass, int timeToLive, NSec3HashAlgorithm hashAlgorithm, NSec3Flags flags, ushort iterations, byte[] salt, byte[] nextHashedOwner, List<RecordType> types)
			: base(name, RecordType.NSec3, recordClass, timeToLive)
		{
			HashAlgorithm = hashAlgorithm;
			Flags = flags;
			Iterations = iterations;
			Salt = salt ?? new byte[] { };
			NextHashedOwner = nextHashedOwner ?? new byte[] { };

			if ((types == null) || (types.Count == 0))
			{
				Types = new List<RecordType>();
			}
			else
			{
				Types = types.Distinct().OrderBy(x => x).ToList();
			}
		}

		internal override string RecordDataToString()
		{
			return (byte) HashAlgorithm
			       + " " + (byte) Flags
			       + " " + Iterations
			       + " " + ((Salt.Length == 0) ? "-" : Salt.ToBase16String())
			       + " " + NextHashedOwner.ToBase32String()
			       + " " + String.Join(" ", Types.Select(RecordTypeHelper.ToShortString));
		}

		protected internal override int MaximumRecordDataLength => 6 + Salt.Length + NextHashedOwner.Length + NSecRecord.GetMaximumTypeBitmapLength(Types);

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			messageData[currentPosition++] = (byte) HashAlgorithm;
			messageData[currentPosition++] = (byte) Flags;
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Iterations);
			messageData[currentPosition++] = (byte) Salt.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Salt);
			messageData[currentPosition++] = (byte) NextHashedOwner.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, NextHashedOwner);

			if (Types.Count > 0)
				NSecRecord.EncodeTypeBitmap(messageData, ref currentPosition, Types);
		}

		internal bool IsCovering(DomainName name)
		{
			DomainName nextDomainName = new DomainName(NextHashedOwner.ToBase32String(), name.GetParentName());

			if (Name.CompareTo(nextDomainName) < 0)
			{
				return ((name.CompareTo(Name) > 0) && (name.CompareTo(nextDomainName) < 0));
			}
			else
			{
				return ((name.CompareTo(nextDomainName) < 0) || (name.CompareTo(Name) > 0));
			}
		}
	}
}