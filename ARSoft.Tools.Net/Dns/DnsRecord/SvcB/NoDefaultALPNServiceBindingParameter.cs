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
///   <para>No support for default protocol binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
// ReSharper disable once InconsistentNaming
// ReSharper disable once IdentifierTypo
public class NoDefaultALPNServiceBindingParameter : ServiceBindingParameterBase
{
	// ReSharper disable once CommentTypo
	/// <summary>
	///   Creates a new instance of the NoDefaultALPNServiceBindingParameter class
	/// </summary>
	// ReSharper disable once IdentifierTypo
	public NoDefaultALPNServiceBindingParameter() { }

	// ReSharper disable once IdentifierTypo
	internal NoDefaultALPNServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength) { }

	// ReSharper disable once IdentifierTypo
	internal NoDefaultALPNServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (parameter != null)
			throw new FormatException();
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.NoDefaultALPN;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical) { }

	protected override int ValueDataLength => 0;

	protected override string ValueToString()
	{
		return String.Empty;
	}
}