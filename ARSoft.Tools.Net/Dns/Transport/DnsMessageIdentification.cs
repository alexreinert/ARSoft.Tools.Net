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
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Indentifier of a DNS message consisting TransactioId and optionally a question
	/// </summary>
	public class DnsMessageIdentification : IEquatable<DnsMessageIdentification>
	{
		/// <summary>
		///   The transaction id
		/// </summary>
		public ushort TransactionID { get; }

		/// <summary>
		///   The question
		/// </summary>
		public DnsQuestion? Question { get; }

		private int? _hashCode;

		/// <summary>
		///   Creates a new instance of the DnsMessageIdentification class
		/// </summary>
		/// <param name="transactionId">The transaction id</param>
		/// <param name="question">The question</param>
		public DnsMessageIdentification(ushort transactionId, DnsQuestion? question)
		{
			TransactionID = transactionId;
			Question = question;
		}

		[SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
		public override int GetHashCode()
		{
			_hashCode ??= (Question?.GetHashCode() ?? 0) ^ TransactionID.GetHashCode();
			return _hashCode.Value;
		}

		public override bool Equals(object? obj)
		{
			return Equals(obj as DnsMessageIdentification);
		}

		public bool Equals(DnsMessageIdentification? other)
		{
			if (other == null)
				return false;

			return TransactionID == other.TransactionID
			       && (Question == null || other.Question == null || Question.Equals(other.Question));
		}

		internal static DnsMessageIdentification Parse(IList<byte> data)
		{
			var pos = 0;
			var transactionID = DnsMessageBase.ParseUShort(data, ref pos);

			pos = 4;
			var queryCount = DnsMessageBase.ParseUShort(data, ref pos);

			if (queryCount == 0)
				return new DnsMessageIdentification(transactionID, null);

			pos = 12;
			return new DnsMessageIdentification(transactionID, DnsQuestion.Parse(data, ref pos));
		}
	}
}