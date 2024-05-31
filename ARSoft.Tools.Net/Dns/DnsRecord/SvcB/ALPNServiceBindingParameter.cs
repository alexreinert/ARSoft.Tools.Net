#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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

using System.Text;

namespace ARSoft.Tools.Net.Dns;

// ReSharper disable once CommentTypo
/// <summary>
///   <para>ALPN service binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
// ReSharper disable once InconsistentNaming
// ReSharper disable once IdentifierTypo
internal class ALPNServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   List of Additional supported protocol identifier
	/// </summary>
	// ReSharper disable once InconsistentNaming
	// ReSharper disable once IdentifierTypo
	public byte[][] ALPNIdentifier { get; }


	/// <summary>
	///   Creates a new instance of the ALPNServiceBindingParameter class
	/// </summary>
	/// <param name="identifier"> List of Additional supported protocol identifier </param>
	// ReSharper disable once IdentifierTypo
	public ALPNServiceBindingParameter(byte[][] identifier)
	{
		ALPNIdentifier = identifier;
	}

	// ReSharper disable once IdentifierTypo
	internal ALPNServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		var endPosition = currentPosition + valueLength;

		var identifier = new List<byte[]>();
		while (currentPosition < endPosition)
		{
			// ReSharper disable once IdentifierTypo
			var alpnLength = (int) resultData[currentPosition++];
			identifier.Add(DnsMessageBase.ParseByteData(resultData, ref currentPosition, alpnLength));
		}

		ALPNIdentifier = identifier.ToArray();
	}

	// ReSharper disable once IdentifierTypo
	internal ALPNServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (String.IsNullOrWhiteSpace(parameter))
			throw new FormatException();

		ALPNIdentifier = parameter.SplitWithQuoting(new[] { ',' }).Select(DecodeIdentifier).ToArray();
	}

	private static byte[] DecodeIdentifier(string s)
	{
		var bytes = new byte[s.Length];
		var bytesPos = 0;

		for (var i = 0; i < s.Length; i++)
		{
			if (s[i] == '\\')
			{
				i++;
				if (i >= s.Length)
					throw new FormatException();
				bytes[bytesPos++] = (byte) s[i];
			}
			else
			{
				bytes[bytesPos++] = (byte) s[i];
			}
		}

		return bytes[0..bytesPos];
	}

	private static string EncodeIdentifier(byte[] bytes)
	{
		var sb = new StringBuilder();

		for (var i = 0; i < bytes.Length; i++)
		{
			switch (bytes[i])
			{
				case 44: // Comma
					sb.Append(@"\,");
					break;
				case 92: // Backslash
					sb.Append(@"\\");
					break;
				default:
					sb.Append((char) bytes[i]);
					break;
			}
		}

		return sb.ToString();
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.ALPN;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		// ReSharper disable once IdentifierTypo
		foreach (var alpn in ALPNIdentifier)
		{
			messageData[currentPosition++] = (byte) alpn.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, alpn);
		}
	}

	protected override int ValueDataLength => ALPNIdentifier.Length + ALPNIdentifier.Sum(x => x.Length);

	protected override string ValueToString()
	{
		return "\"" + String.Join(',', ALPNIdentifier.Select(EncodeIdentifier)).ToMasterfileLabelRepresentation() + "\"";
	}
}