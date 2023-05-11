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

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>The EDNS(0) Padding Option</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc7830.html">RFC 7830</a>.
///   </para>
/// </summary>
public class PaddingOption : EDnsOptionBase
{
	/// <summary>
	///   The padding
	/// </summary>
	public byte[]? Padding { get; }

	internal PaddingOption(IList<byte> resultData, int startPosition, int length)
		: base(EDnsOptionType.Padding)
	{
		Padding = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
	}

	/// <summary>
	///   Creates a new instance of the PaddingOption class
	/// </summary>
	/// <param name="padding">The padding</param>
	public PaddingOption(byte[]? padding = null)
		: base(EDnsOptionType.Padding)
	{
		Padding = padding;
	}

	internal override ushort DataLength => (ushort) (Padding?.Length ?? 0);

	internal override void EncodeData(IList<byte> messageData, ref int currentPosition)
	{
		DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Padding);
	}
}