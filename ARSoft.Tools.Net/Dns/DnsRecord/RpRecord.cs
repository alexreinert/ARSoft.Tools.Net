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
	///   <para>Responsible person record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
	///   </para>
	/// </summary>
	public class RpRecord : DnsRecordBase
	{
		/// <summary>
		///   Mail address of responsable person, the @ should be replaced by a dot
		/// </summary>
		public DomainName MailBox { get; protected set; }

		/// <summary>
		///   Domain name of a <see cref="TxtRecord" /> with additional information
		/// </summary>
		public DomainName TxtDomainName { get; protected set; }

		internal RpRecord() {}

		/// <summary>
		///   Creates a new instance of the RpRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="mailBox"> Mail address of responsable person, the @ should be replaced by a dot </param>
		/// <param name="txtDomainName">
		///   Domain name of a <see cref="TxtRecord" /> with additional information
		/// </param>
		public RpRecord(DomainName name, int timeToLive, DomainName mailBox, DomainName txtDomainName)
			: base(name, RecordType.Rp, RecordClass.INet, timeToLive)
		{
			MailBox = mailBox ?? DomainName.Root;
			TxtDomainName = txtDomainName ?? DomainName.Root;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			MailBox = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
			TxtDomainName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length != 2)
				throw new FormatException();

			MailBox = ParseDomainName(origin, stringRepresentation[0]);
			TxtDomainName = ParseDomainName(origin, stringRepresentation[1]);
		}

		internal override string RecordDataToString()
		{
			return MailBox
			       + " " + TxtDomainName;
		}

		protected internal override int MaximumRecordDataLength => 4 + MailBox.MaximumRecordDataLength + TxtDomainName.MaximumRecordDataLength;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, MailBox, null, useCanonical);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, TxtDomainName, null, useCanonical);
		}
	}
}