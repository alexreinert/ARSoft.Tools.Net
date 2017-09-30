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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Base record class for storing text labels (TxtRecord and SpfRecord)
	/// </summary>
	public abstract class TextRecordBase : DnsRecordBase, ITextRecord
	{
		protected TextRecordBase() {}

		protected TextRecordBase(DomainName name, RecordType recordType, int timeToLive, string textData)
			: this(name, recordType, timeToLive, new List<string> { textData ?? String.Empty }) {}

		protected TextRecordBase(DomainName name, RecordType recordType, int timeToLive, IEnumerable<string> textParts)
			: base(name, recordType, RecordClass.INet, timeToLive)
		{
			TextParts = new List<string>(textParts);
		}

		/// <summary>
		///   Text data
		/// </summary>
		public string TextData => String.Join(String.Empty, TextParts);

		/// <summary>
		///   The single parts of the text data
		/// </summary>
		public IEnumerable<string> TextParts { get; protected set; }

		protected internal override int MaximumRecordDataLength
		{
			get { return TextParts.Sum(p => p.Length + (p.Length / 255) + (p.Length % 255 == 0 ? 0 : 1)); }
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			int endPosition = startPosition + length;

			List<string> textParts = new List<string>();
			while (startPosition < endPosition)
			{
				textParts.Add(DnsMessageBase.ParseText(resultData, ref startPosition));
			}

			TextParts = textParts;
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			if (stringRepresentation.Length == 0)
				throw new FormatException();

			TextParts = stringRepresentation;
		}

		internal override string RecordDataToString()
		{
			return String.Join(" ", TextParts.Select(x => "\"" + x.ToMasterfileLabelRepresentation() + "\""));
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			foreach (var part in TextParts)
			{
				DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, part);
			}
		}
	}
}