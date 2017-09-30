#region Copyright and License
// Copyright 2010 Alexander Reinert
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
		NoError = 0,
		FormatError = 1,
		ServerFailure = 2,
		NxDomain = 3,
		NotImplemented = 4,
		Refused = 5,

		YXDomain = 6,
		YXRRSet = 7,
		NXRRSet = 8,
		NotAuthoritive = 9,
		NotZone = 10,

		BadVersion = 16,
		BadSig = 16,
		BadKey = 17,
		BadTime = 18,
		BadMode = 19,
		BadName = 20,
		BadAlg = 21,
		BadTrunc = 22,
	}
}