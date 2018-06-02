﻿#region Copyright and License
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

using System.Collections.Generic;

namespace ARSoft.Tools.Net.Dns.DynamicUpdate
{
    /// <summary>
    ///   Prequisite, that a name exists
    /// </summary>
    public class NameIsInUsePrequisite : PrequisiteBase
	{
		internal NameIsInUsePrequisite() {}

		/// <summary>
		///   Creates a new instance of the NameIsInUsePrequisite class
		/// </summary>
		/// <param name="name"> Name that should be checked </param>
		public NameIsInUsePrequisite(DomainName name)
			: base(name, RecordType.Any, RecordClass.Any, 0) {}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length) {}

		protected internal override int MaximumRecordDataLength => 0;

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical) {}
	}
}