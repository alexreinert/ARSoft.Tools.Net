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

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Base class for a dns name identity
	/// </summary>
	public abstract class DnsMessageEntryBase : IEquatable<DnsMessageEntryBase>
	{
		/// <summary>
		///   Domain name
		/// </summary>
		public DomainName Name { get; protected set; }

		/// <summary>
		///   Type of the record
		/// </summary>
		public RecordType RecordType { get; protected set; }

		/// <summary>
		///   Class of the record
		/// </summary>
		public RecordClass RecordClass { get; protected set; }

		internal abstract int MaximumLength { get; }

		protected DnsMessageEntryBase(DomainName name, RecordType recordType, RecordClass recordClass)
		{
			_ = name ?? throw new ArgumentNullException(nameof(name));

			Name = name;
			RecordType = recordType;
			RecordClass = recordClass;
		}

		/// <summary>
		///   Returns the textual representation
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			return Name + " " + RecordType + " " + RecordClass;
		}

		private int? _hashCode;

		[SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
		public override int GetHashCode()
		{
			if (!_hashCode.HasValue)
			{
				_hashCode = ToString().GetHashCode();
			}

			return _hashCode.Value;
		}

		public override bool Equals(object? obj)
		{
			return Equals(obj as DnsMessageEntryBase);
		}

		public bool Equals(DnsMessageEntryBase? other)
		{
			return other != null
			       && Name.Equals(other.Name)
			       && RecordType.Equals(other.RecordType)
			       && RecordClass.Equals(other.RecordClass);
		}
	}
}