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
	///   <para>Uniform Resource Identifier</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc7553">RFC 7553</see>
	///   </para>
	/// </summary>
	public class UriRecord : DnsRecordBase
	{
		/// <summary>
		///   Priority
		/// </summary>
		public ushort Priority { get; private set; }

		/// <summary>
		///   Weight
		/// </summary>
		public ushort Weight { get; private set; }

		/// <summary>
		///   Target
		/// </summary>
		public string Target { get; private set; }

		internal UriRecord() {}

		/// <summary>
		///   Creates a new instance of the MxRecord class
		/// </summary>
		/// <param name="name"> Name of the zone </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="priority"> Priority of the record </param>
		/// <param name="weight"> Weight of the record </param>
		/// <param name="target"> Target of the record </param>
		public UriRecord(DomainName name, int timeToLive, ushort priority, ushort weight, string target)
			: base(name, RecordType.Uri, RecordClass.INet, timeToLive)
		{
			Priority = priority;
			Weight = weight;
			Target = target ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Priority = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Weight = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Target = DnsMessageBase.ParseText(resultData, ref startPosition, length - 4);
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length != 3)
				throw new FormatException();

			Priority = UInt16.Parse(stringRepresentation[0]);
			Weight = UInt16.Parse(stringRepresentation[1]);
			Target = stringRepresentation[2];
		}

		internal override string RecordDataToString()
		{
			return Priority + " " + Weight
			       + " \"" + Target + "\"";
		}

		protected internal override int MaximumRecordDataLength => Target.Length + 4;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Priority);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Weight);
			DnsMessageBase.EncodeTextWithoutLength(messageData, ref currentPosition, Target);
		}
	}
}