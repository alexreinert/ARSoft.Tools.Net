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

namespace ARSoft.Tools.Net.Dns.DynamicUpdate;

/// <summary>
///   Prequisite, that a record with given values exists
/// </summary>
public class RecordExistsValueIndependantPrequisite : PrequisiteBase
{
	/// <summary>
	///   RecordType that should be checked
	/// </summary>
	public RecordType RecordType { get; }

	/// <summary>
	///   Creates a new instance of the RecordExistsValueIndependantPrequisite class
	/// </summary>
	/// <param name="name"> Name that should be checked </param>
	/// <param name="recordType"> RecordType that should be checked </param>
	public RecordExistsValueIndependantPrequisite(DomainName name, RecordType recordType)
		: base(name)
	{
		RecordType = recordType;
	}

	protected override RecordType RecordTypeInternal => RecordType;

	protected override RecordClass RecordClassInternal => RecordClass.Any;
}