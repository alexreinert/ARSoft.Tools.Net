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
///   Base class of a Service Binding Parameter
/// </summary>
public abstract class ServiceBindingParameterBase
{
	/// <summary>
	///   Key of the service binding parameter
	/// </summary>
	public abstract ServiceBindingParameterKey Key { get; }

	protected internal void EncodeParameterData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Key);
		var lengthPosition = currentPosition;
		currentPosition += 2;
		EncodeValueData(messageData, ref currentPosition, useCanonical);
		var length = currentPosition - lengthPosition - 2;
		DnsMessageBase.EncodeUShort(messageData, ref lengthPosition, (ushort) length);
	}

	protected abstract void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical);

	protected internal int MaximumRecordDataLength => 4 + ValueDataLength;

	protected abstract int ValueDataLength { get; }

	internal static ServiceBindingParameterBase ParseServiceBindingParameter(IList<byte> resultData, ref int currentPosition)
	{
		var type = (ServiceBindingParameterKey) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
		var valueLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);

		switch (type)
		{
			case ServiceBindingParameterKey.Mandatory:
				return new MandatoryServiceBindingParameter(resultData, ref currentPosition, valueLength);

			case ServiceBindingParameterKey.ALPN:
				return new ALPNServiceBindingParameter(resultData, ref currentPosition, valueLength);

			case ServiceBindingParameterKey.NoDefaultALPN:
				return new NoDefaultALPNServiceBindingParameter(resultData, ref currentPosition, valueLength);

			case ServiceBindingParameterKey.Port:
				return new PortServiceBindingParameter(resultData, ref currentPosition, valueLength);

			case ServiceBindingParameterKey.IPv4Hint:
				return new IPv4HintBindingParameter(resultData, ref currentPosition, valueLength);

			case ServiceBindingParameterKey.IPv6Hint:
				return new IPv6HintBindingParameter(resultData, ref currentPosition, valueLength);

			default:
				return new UnknownServiceBindingParameter(type, resultData, ref currentPosition, valueLength);
		}
	}

	internal static ServiceBindingParameterBase ParseServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		switch (type)
		{
			case ServiceBindingParameterKey.Mandatory:
				return new MandatoryServiceBindingParameter(type, parameter);

			case ServiceBindingParameterKey.ALPN:
				return new ALPNServiceBindingParameter(type, parameter);

			case ServiceBindingParameterKey.NoDefaultALPN:
				return new NoDefaultALPNServiceBindingParameter(type, parameter);

			case ServiceBindingParameterKey.Port:
				return new PortServiceBindingParameter(type, parameter);

			case ServiceBindingParameterKey.IPv4Hint:
				return new IPv4HintBindingParameter(type, parameter);

			case ServiceBindingParameterKey.IPv6Hint:
				return new IPv6HintBindingParameter(type, parameter);

			default:
				return new UnknownServiceBindingParameter(type, parameter);
		}
	}

	protected abstract string ValueToString();

	public sealed override string ToString()
	{
		if (ValueDataLength == 0)
		{
			return ServiceBindingParameterKeyHelper.ToString(Key);
		}
		else
		{
			return ServiceBindingParameterKeyHelper.ToString(Key) + "=" + ValueToString();
		}
	}
}