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

internal static class ServiceBindingParameterKeyHelper
{
	public static string ToString(ServiceBindingParameterKey type)
	{
		switch (type)
		{
			case ServiceBindingParameterKey.Mandatory:
				return "mandatory";
			case ServiceBindingParameterKey.ALPN:
				return "alpn";
			case ServiceBindingParameterKey.NoDefaultALPN:
				return "no-default-alpn";
			case ServiceBindingParameterKey.Port:
				return "port";
			case ServiceBindingParameterKey.IPv4Hint:
				return "ipv4hint";
			case ServiceBindingParameterKey.IPv6Hint:
				return "ipv6hint";
			default:
				return "key" + ((ushort) type);
		}
	}

	public static ServiceBindingParameterKey Parse(string value)
	{
		switch (value)
		{
			case "mandatory":
				return ServiceBindingParameterKey.Mandatory;
			case "alpn":
				return ServiceBindingParameterKey.ALPN;
			case "no-default-alpn":
				return ServiceBindingParameterKey.NoDefaultALPN;
			case "port":
				return ServiceBindingParameterKey.Port;
			case "ipv4hint":
				return ServiceBindingParameterKey.IPv4Hint;
			case "ipv6hint":
				return ServiceBindingParameterKey.IPv6Hint;
		}

		if (value.Length > 3 && value.StartsWith("key") && UInt16.TryParse(value[3..], out var typeValue))
		{
			return (ServiceBindingParameterKey) typeValue;
		}

		throw new FormatException("Invalid or unknown SvcParamKey");
	}
}