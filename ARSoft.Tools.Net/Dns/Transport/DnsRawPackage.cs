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

using System.Collections;
using System.Text;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   A wrapper around the buffer of a raw DNS package byte buffer
///   The first two bytes are reserved for the length header
/// </summary>
public class DnsRawPackage
{
	/// <summary>
	///   Length of the length header
	/// </summary>
	public const int LENGTH_HEADER_LENGTH = sizeof(ushort);

	private readonly ArraySegment<byte> _dataWithLengthHeader;

	/// <summary>
	///   The identification of the dns message
	/// </summary>
	public DnsMessageIdentification MessageIdentification { get; }

	/// <summary>
	///   Gets the length of the raw DNS package without length header
	/// </summary>
	public int Length { get; }

	/// <summary>
	///   Creates a new instance of the DnsRawPackage class
	/// </summary>
	/// <param name="buffer"> Raw data of the DNS package including the length header</param>
	public DnsRawPackage(byte[] buffer)
	{
		var tmp = 0;
		Length = DnsMessageBase.ParseUShort(buffer, ref tmp);
		MessageIdentification = DnsMessageIdentification.Parse(buffer[LENGTH_HEADER_LENGTH..]);
		_dataWithLengthHeader = buffer;
	}

	internal DnsRawPackage(ArraySegment<byte> data, int length)
	{
		Length = length;
		MessageIdentification = DnsMessageIdentification.Parse(data[LENGTH_HEADER_LENGTH..]);
		_dataWithLengthHeader = data;
	}

	/// <summary>
	///   Gets the data of the the raw DNS package
	/// </summary>
	/// <param name="includeLengthHeader"> A value indicating, if the length header should be included </param>
	/// <returns> The data of the raw DNS package </returns>
	public ArraySegment<byte> ToArraySegment(bool includeLengthHeader)
	{
		if (includeLengthHeader)
		{
			DnsMessageBase.EncodeUShort(_dataWithLengthHeader, 0, (ushort) Length);
			return _dataWithLengthHeader;
		}
		else
		{
			return _dataWithLengthHeader[LENGTH_HEADER_LENGTH..];
		}
	}
}