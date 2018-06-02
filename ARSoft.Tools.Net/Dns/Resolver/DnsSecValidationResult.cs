#region Copyright and License
// Copyright 2010..2017 Alexander Reinert
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

namespace ARSoft.Tools.Net.Dns.Resolver
{
	/// <summary>
	///   The result of a DNSSEC validation
	/// </summary>
	public enum DnsSecValidationResult
	{
		/// <summary>
		///   It is indeterminate whether the validation is secure, insecure or bogus
		/// </summary>
		Indeterminate,

		/// <summary>
		///   The response is signed and fully validated
		/// </summary>
		Signed,

		/// <summary>
		///   The response is unsigned with a validated OptOut
		/// </summary>
		Unsigned,

		/// <summary>
		///   The response is bogus
		/// </summary>
		Bogus,
	}
}