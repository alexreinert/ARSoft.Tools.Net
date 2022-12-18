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
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>NID</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc6742.html">RFC 6742</a>.
	///   </para>
	/// </summary>
	public class NIdRecord : DnsRecordBase
	{
		/// <summary>
		///   The preference
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   The Node ID
		/// </summary>
		public ulong NodeID { get; private set; }

		internal NIdRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			NodeID = DnsMessageBase.ParseULong(resultData, ref currentPosition);
		}

		internal NIdRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			if (stringRepresentation.Length != 2)
				throw new FormatException();

			Preference = UInt16.Parse(stringRepresentation[0]);

			string[] nodeIDParts = stringRepresentation[1].Split(':');

			if (nodeIDParts.Length != 4)
				throw new FormatException();

			for (int i = 0; i < 4; i++)
			{
				if (nodeIDParts[i].Length != 4)
					throw new FormatException();

				NodeID = NodeID << 16;
				NodeID |= Convert.ToUInt16(nodeIDParts[i], 16);
			}
		}

		/// <summary>
		///   Creates a new instance of the NIdRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="preference"> The preference </param>
		/// <param name="nodeID"> The Node ID </param>
		public NIdRecord(DomainName name, int timeToLive, ushort preference, ulong nodeID)
			: base(name, RecordType.NId, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			NodeID = nodeID;
		}

		internal override string RecordDataToString()
		{
			string nodeID = NodeID.ToString("x16");
			return Preference + " " + nodeID.Substring(0, 4) + ":" + nodeID.Substring(4, 4) + ":" + nodeID.Substring(8, 4) + ":" + nodeID.Substring(12);
		}

		protected internal override int MaximumRecordDataLength => 10;

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeULong(messageData, ref currentPosition, NodeID);
		}
	}
}