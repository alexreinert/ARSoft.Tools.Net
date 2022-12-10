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
using System.Xml.Linq;

namespace ARSoft.Tools.Net.Dns.DynamicUpdate
{
	/// <summary>
	///   <para>Dynamic DNS update message</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc2136.html">RFC 2136</a>.
	///   </para>
	/// </summary>
	public class DnsUpdateMessage : DnsMessageBase
	{
		/// <summary>
		///   Parses a the contents of a byte array as DnsUpdateMessage
		/// </summary>
		/// <param name="data">Buffer, that contains the message data</param>
		/// <returns>A new instance of the DnsUpdateMessage class</returns>
		public static DnsUpdateMessage Parse(byte[] data)
		{
			return Parse<DnsUpdateMessage>(data);
		}

		/// <summary>
		///   Creates a new instance of the DnsUpdateMessage class
		/// </summary>
		public DnsUpdateMessage()
		{
			OperationCode = OperationCode.Update;
		}

		private List<PrequisiteBase> _prequisites = new List<PrequisiteBase>();
		private List<UpdateBase> _updates = new List<UpdateBase>();

		/// <summary>
		///   Gets or sets the zone name
		/// </summary>
		public DomainName ZoneName { get; set; } = DomainName.Root;

		/// <summary>
		///   Gets or sets the entries in the prerequisites section
		/// </summary>
		public List<PrequisiteBase> Prequisites
		{
			get { return _prequisites ??= new List<PrequisiteBase>(); }
			set { _prequisites = value; }
		}

		/// <summary>
		///   Gets or sets the entries in the update section
		/// </summary>
		public List<UpdateBase> Updates
		{
			get { return _updates ??= new List<UpdateBase>(); }
			set { _updates = value; }
		}

		/// <summary>
		///   Creates a new instance of the DnsUpdateMessage as response to the current instance
		/// </summary>
		/// <returns>A new instance of the DnsUpdateMessage as response to the current instance</returns>
		public DnsUpdateMessage CreateResponseInstance()
		{
			DnsUpdateMessage result = new DnsUpdateMessage()
			{
				TransactionID = TransactionID,
				IsEDnsEnabled = IsEDnsEnabled,
				IsQuery = false,
				OperationCode = OperationCode,
				ZoneName = ZoneName,
			};

			if (IsEDnsEnabled)
			{
				result.EDnsOptions!.Version = EDnsOptions!.Version;
				result.EDnsOptions!.UdpPayloadSize = EDnsOptions!.UdpPayloadSize;
			}

			return result;
		}

		protected internal override DnsMessageBase CreateFailureResponse()
		{
			DnsUpdateMessage msg = CreateResponseInstance();
			msg.ReturnCode = ReturnCode.ServerFailure;
			return msg;
		}

		internal override bool IsTcpUsingRequested => false;

		internal override bool IsTcpResendingRequested => false;

		internal override bool IsTcpNextMessageWaiting(bool isSubsequentResponseMessage)
		{
			return false;
		}

		protected override void ParseSections(byte[] data, ref int currentPosition)
		{
			int questionCount = ParseUShort(data, ref currentPosition);
			int prequisitesCount = ParseUShort(data, ref currentPosition);
			int updatesCount = ParseUShort(data, ref currentPosition);
			int additionalRecordCount = ParseUShort(data, ref currentPosition);

			List<DnsQuestion> questions = new List<DnsQuestion>();
			ParseQuestionSection(data, ref currentPosition, questions, questionCount);
			ZoneName = questions.Count == 1 && questions[0].RecordType == RecordType.Soa && questions[0].RecordClass == RecordClass.INet ? questions[0].Name : DomainName.Root;

			for (int i = 0; i < prequisitesCount; i++)
			{
				Prequisites.Add(PrequisiteBase.ParsePrequisiteFromMessage(data, ref currentPosition));
			}

			for (int i = 0; i < updatesCount; i++)
			{
				Updates.Add(UpdateBase.ParseUpdateFromMessage(data, ref currentPosition));
			}

			ParseRecordSection(data, ref currentPosition, AdditionalRecords, additionalRecordCount);
		}

		protected override int GetSectionsMaxLength()
		{
			return 12
			       + ZoneName.MaximumRecordDataLength + 6
			       + Prequisites.Sum(record => record.MaximumLength)
			       + Updates.Sum(record => record.MaximumLength)
			       + AdditionalRecords.Sum(record => record.MaximumLength);
		}

		protected override void EncodeSections(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames)
		{
			EncodeUShort(messageData, ref currentPosition, 1);
			EncodeUShort(messageData, ref currentPosition, (ushort) Prequisites.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort) Updates.Count);
			EncodeUShort(messageData, ref currentPosition, (ushort) AdditionalRecords.Count);

			new DnsQuestion(ZoneName, RecordType.Soa, RecordClass.INet).Encode(messageData, offset, ref currentPosition, domainNames);
			foreach (PrequisiteBase prequisite in Prequisites)
			{
				prequisite.Encode(messageData, offset, ref currentPosition, domainNames);
			}

			foreach (UpdateBase update in Updates)
			{
				update.Encode(messageData, offset, ref currentPosition, domainNames);
			}

			foreach (DnsRecordBase record in AdditionalRecords)
			{
				record.Encode(messageData, offset, ref currentPosition, domainNames);
			}
		}

		//protected override void FinishParsing()
		//{
		//	Updates =
		//		AuthorityRecords.ConvertAll<UpdateBase>(
		//			record =>
		//			{
		//				if (record.TimeToLive != 0)
		//				{
		//					return new AddRecordUpdate(record);
		//				}
		//				else if ((record.RecordType == RecordType.Any) && (record.RecordClass == RecordClass.Any) && (record.RecordDataLength == 0))
		//				{
		//					return new DeleteAllRecordsUpdate(record.Name);
		//				}
		//				else if ((record.RecordClass == RecordClass.Any) && (record.RecordDataLength == 0))
		//				{
		//					return new DeleteRecordUpdate(record.Name, record.RecordType);
		//				}
		//				else if (record.RecordClass == RecordClass.None)
		//				{
		//					return new DeleteRecordUpdate(record);
		//				}
		//				else
		//				{
		//					return null;
		//				}
		//			}).Where(update => (update != null)).ToList();
		//}

		internal override bool ValidateResponse(DnsMessageBase responseBase)
		{
			DnsUpdateMessage? response = responseBase as DnsUpdateMessage;

			if (response == null)
				return false;

			if (TransactionID != response.TransactionID)
				return false;

			if ((response.ReturnCode == ReturnCode.NoError) || (response.ReturnCode == ReturnCode.NxDomain))
			{
				return response.ZoneName.Equals(ZoneName, false);
			}

			return true;
		}

		protected internal override void Add0x20Bits()
		{
			ZoneName = ZoneName.Add0x20Bits();
		}

		protected internal override void AddSubsequentResponse(DnsMessageBase respone)
		{
			throw new NotSupportedException();
		}

		protected internal override bool AllowMultipleResponses => false;

		protected internal override IEnumerable<DnsMessageBase> SplitResponse()
		{
			throw new NotSupportedException();
		}
	}
}