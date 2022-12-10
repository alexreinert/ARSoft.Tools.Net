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

namespace ARSoft.Tools.Net.Dns.DynamicUpdate
{
	/// <summary>
	///   Base update action of dynamic dns update
	/// </summary>
	public abstract class UpdateBase
	{
		/// <summary>
		///   Domain name
		/// </summary>
		public DomainName Name { get; private set; }

		protected virtual int MaximumRecordDataLength => 0;

		internal int MaximumLength => Name.MaximumRecordDataLength + 12 + MaximumRecordDataLength;

		protected abstract RecordType RecordTypeInternal { get; }

		protected abstract RecordClass RecordClassInternal { get; }

		protected abstract int TimeToLive { get; }

		protected UpdateBase(DomainName name)
		{
			_ = name ?? throw new ArgumentNullException(nameof(name));

			Name = name;
		}

		internal void Encode(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical = false)
		{
			EncodeRecordHeader(messageData, offset, ref currentPosition, domainNames, useCanonical);
			EncodeRecordBody(messageData, offset, ref currentPosition, domainNames, useCanonical);
		}

		internal void EncodeRecordHeader(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Name, domainNames, useCanonical);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordTypeInternal);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordClassInternal);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, TimeToLive);
		}

		internal void EncodeRecordBody(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			int recordDataOffset = currentPosition + 2;
			EncodeRecordData(messageData, offset, ref recordDataOffset, domainNames, useCanonical);
			EncodeRecordLength(messageData, offset, ref currentPosition, domainNames, recordDataOffset);
		}

		internal void EncodeRecordLength(byte[] messageData, int offset, ref int recordDataOffset, Dictionary<DomainName, ushort> domainNames, int recordPosition)
		{
			DnsMessageBase.EncodeUShort(messageData, ref recordDataOffset, (ushort) (recordPosition - recordDataOffset - 2));
			recordDataOffset = recordPosition;
		}

		protected virtual void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical) { }

		internal static UpdateBase ParseUpdateFromMessage(byte[] resultData, ref int currentPosition)
		{
			int startPosition = currentPosition;
			DomainName name = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
			RecordType recordType = (RecordType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);

			RecordClass recordClass = (RecordClass) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int timeToLive = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			ushort recordDataLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);

			int recordDataPosition = currentPosition;
			currentPosition += recordDataLength;

			if (timeToLive == 0)
			{
				if (recordDataLength == 0)
				{
					return new DeleteAllRecordsUpdate(name, recordType);
				}
				else
				{
					DnsRecordBase record = DnsRecordBase.ParseRecordFromBinary(startPosition, name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
					return new DeleteRecordUpdate(record);
				}
			}
			else
			{
				DnsRecordBase record = DnsRecordBase.ParseRecordFromBinary(startPosition, name, recordType, recordClass, timeToLive, resultData, recordDataPosition, recordDataLength);
				return new AddRecordUpdate(record);
			}
		}
	}
}