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
using System.Text.Json.Serialization;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Message returned as result to a LLMNR query
	/// </summary>
	[JsonConverter(typeof(Rfc8427JsonConverter<LlmnrMessage>))]
	public class LlmnrMessage : DnsRecordMessageBase
	{
		/// <summary>
		///   Parses a the contents of a byte array as LlmnrMessage
		/// </summary>
		/// <param name="data">Buffer, that contains the message data</param>
		/// <returns>A new instance of the LlmnrMessage class</returns>
		public static LlmnrMessage Parse(byte[] data)
		{
			return Parse<LlmnrMessage>(data);
		}

		#region Header
		/// <summary>
		///   <para>Gets or sets the conflict (C) flag</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4795.html">RFC 4795</a>.
		///   </para>
		/// </summary>
		public bool IsConflict
		{
			get => AAFlagInternal;
			set => AAFlagInternal = value;
		}

		/// <summary>
		///   <para>Gets or sets the truncated response (TC) flag</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4795.html">RFC 4795</a>.
		///   </para>
		/// </summary>
		public bool IsTruncated
		{
			get => TCFlagInternal;
			set => TCFlagInternal = value;
		}

		/// <summary>
		///   <para>Gets or sets the tentive (T) flag</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4795.html">RFC 4795</a>.
		///   </para>
		/// </summary>
		public bool IsTentive
		{
			get => RDFlagInternal;
			set => RDFlagInternal = value;
		}
		#endregion

		internal override bool IsReliableSendingRequested => false;

		internal override bool IsReliableResendingRequested => IsTruncated;

		internal override bool IsNextMessageWaiting(bool isSubsequentResponseMessage)
		{
			return false;
		}

		protected internal override DnsMessageBase CreateFailureResponse()
		{
			throw new NotSupportedException();
		}
	}
}