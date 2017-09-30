#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
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
	///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
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
		public byte Flags { get; private set; }

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
		public byte[] NextHashedOwnerName { get; internal set; }

		/// <summary>
		///   Types of next owner
		/// </summary>
		public List<RecordType> Types { get; private set; }

		internal NSec3Record() {}

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
		/// <param name="nextHashedOwnerName"> Binary data of hash of next owner </param>
		/// <param name="types"> Types of next owner </param>
		public NSec3Record(DomainName name, RecordClass recordClass, int timeToLive, NSec3HashAlgorithm hashAlgorithm, byte flags, ushort iterations, byte[] salt, byte[] nextHashedOwnerName, List<RecordType> types)
			: base(name, RecordType.NSec3, recordClass, timeToLive)
		{
			HashAlgorithm = hashAlgorithm;
			Flags = flags;
			Iterations = iterations;
			Salt = salt ?? new byte[] { };
			NextHashedOwnerName = nextHashedOwnerName ?? new byte[] { };

			if ((types == null) || (types.Count == 0))
			{
				Types = new List<RecordType>();
			}
			else
			{
				Types = types.Distinct().OrderBy(x => x).ToList();
			}
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			HashAlgorithm = (NSec3HashAlgorithm) resultData[currentPosition++];
			Flags = resultData[currentPosition++];
			Iterations = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int saltLength = resultData[currentPosition++];
			Salt = DnsMessageBase.ParseByteData(resultData, ref currentPosition, saltLength);
			int hashLength = resultData[currentPosition++];
			NextHashedOwnerName = DnsMessageBase.ParseByteData(resultData, ref currentPosition, hashLength);
			Types = NSecRecord.ParseTypeBitMap(resultData, ref currentPosition, endPosition);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length < 5)
				throw new FormatException();

			HashAlgorithm = (NSec3HashAlgorithm) Byte.Parse(stringRepresentation[0]);
			Flags = Byte.Parse(stringRepresentation[1]);
			Iterations = UInt16.Parse(stringRepresentation[2]);
			Salt = (stringRepresentation[3] == "-") ? new byte[] { } : stringRepresentation[3].FromBase16String();
			NextHashedOwnerName = stringRepresentation[4].FromBase32HexString();
			Types = stringRepresentation.Skip(5).Select(RecordTypeHelper.ParseShortString).ToList();
		}

		internal override string RecordDataToString()
		{
			return (byte) HashAlgorithm
			       + " " + Flags
			       + " " + Iterations
			       + " " + ((Salt.Length == 0) ? "-" : Salt.ToBase16String())
			       + " " + NextHashedOwnerName.ToBase32HexString()
			       + " " + String.Join(" ", Types.Select(RecordTypeHelper.ToShortString));
		}

		protected internal override int MaximumRecordDataLength => 6 + Salt.Length + NextHashedOwnerName.Length + NSecRecord.GetMaximumTypeBitmapLength(Types);

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			messageData[currentPosition++] = (byte) HashAlgorithm;
			messageData[currentPosition++] = Flags;
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Iterations);
			messageData[currentPosition++] = (byte) Salt.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Salt);
			messageData[currentPosition++] = (byte) NextHashedOwnerName.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, NextHashedOwnerName);

			if (Types.Count > 0)
				NSecRecord.EncodeTypeBitmap(messageData, ref currentPosition, Types);
		}

		internal bool IsCovering(DomainName name)
		{
			DomainName nextDomainName = new DomainName(NextHashedOwnerName.ToBase32HexString(), name.GetParentName());

			return ((name.CompareTo(Name) > 0) && (name.CompareTo(nextDomainName) < 0));
		}
	}
}