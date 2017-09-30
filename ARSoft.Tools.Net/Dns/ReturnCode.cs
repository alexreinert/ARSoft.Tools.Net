#region Copyright and License
// Copyright 2010..11 Alexander Reinert
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

namespace ARSoft.Tools.Net.Dns
{
	public enum ReturnCode : ushort
	{
		NoError = 0, // RFC1035
		FormatError = 1, // RFC1035
		ServerFailure = 2, // RFC1035
		NxDomain = 3, // RFC1035
		NotImplemented = 4, // RFC1035
		Refused = 5, // RFC1035

		YXDomain = 6, // RFC2136
		YXRRSet = 7, // RFC2136
		NXRRSet = 8, // RFC2136
		NotAuthoritive = 9, // RFC2136
		NotZone = 10, // RFC2136

		BadVersion = 16, // RFC2671
		BadSig = 16, // RFC2845
		BadKey = 17, // RFC2845
		BadTime = 18, // RFC2845
		BadMode = 19, // RFC2930
		BadName = 20, // RFC2930
		BadAlg = 21, // RFC2930
		BadTrunc = 22, // RFC4635
	}
}