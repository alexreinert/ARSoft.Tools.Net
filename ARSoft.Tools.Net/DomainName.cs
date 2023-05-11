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
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ARSoft.Tools.Net.Dns;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace ARSoft.Tools.Net
{
	/// <summary>
	///   Represents a domain name
	/// </summary>
	public class DomainName : IEquatable<DomainName>, IComparable<DomainName>
	{
		private readonly string[] _labels;

		/// <summary>
		///   The DNS root name (.)
		/// </summary>
		public static DomainName Root { get; } = new(Array.Empty<string>());

		internal static DomainName Asterisk { get; } = new(new[] { "*" });

		/// <summary>
		///   Creates a new instance of the DomainName class
		/// </summary>
		/// <param name="labels">The labels of the DomainName</param>
		public DomainName(string[] labels)
		{
			_labels = labels;
		}

		internal DomainName(string label, DomainName parent)
		{
			_labels = new string[1 + parent.LabelCount];

			_labels[0] = label;
			Array.Copy(parent._labels, 0, _labels, 1, parent.LabelCount);
		}

		/// <summary>
		///   Gets the labels of the domain name
		/// </summary>
		public string[] Labels => _labels;

		/// <summary>
		///   Gets the count of labels this domain name contains
		/// </summary>
		public int LabelCount => _labels.Length;

		internal int MaximumRecordDataLength
		{
			get { return LabelCount + _labels.Sum(x => x.Length); }
		}

		// ReSharper disable once InconsistentNaming
		internal DomainName Add0x20Bits()
		{
			string[] newLabels = new string[LabelCount];

			for (int i = 0; i < LabelCount; i++)
			{
				newLabels[i] = Labels[i].Add0x20Bits();
			}

			return new DomainName(newLabels) { _hashCode = _hashCode };
		}

		/// <summary>
		///   Gets a parent zone of the domain name
		/// </summary>
		/// <param name="removeLabels">The number of labels to be removed</param>
		/// <returns>The DomainName of the parent zone</returns>
		public DomainName GetParentName(int removeLabels = 1)
		{
			if (removeLabels < 0)
				throw new ArgumentOutOfRangeException(nameof(removeLabels));

			if (removeLabels > LabelCount)
				throw new ArgumentOutOfRangeException(nameof(removeLabels));

			if (removeLabels == 0)
				return this;

			string[] newLabels = new string[LabelCount - removeLabels];
			Array.Copy(_labels, removeLabels, newLabels, 0, newLabels.Length);

			return new DomainName(newLabels);
		}

		/// <summary>
		///   Returns if with domain name equals an other domain name or is a child of it
		/// </summary>
		/// <param name="domainName">The possible equal or parent domain name</param>
		/// <returns>true, if the domain name equals the other domain name or is a child of it; otherwise, false</returns>
		public bool IsEqualOrSubDomainOf(DomainName domainName)
		{
			if (Equals(domainName))
				return true;

			if (domainName.LabelCount >= LabelCount)
				return false;

			return GetParentName(LabelCount - domainName.LabelCount).Equals(domainName);
		}

		/// <summary>
		///   Returns if with domain name is a child of an other domain name
		/// </summary>
		/// <param name="domainName">The possible parent domain name</param>
		/// <returns>true, if the domain name is a child of the other domain; otherwise, false</returns>
		public bool IsSubDomainOf(DomainName domainName)
		{
			if (domainName.LabelCount >= LabelCount)
				return false;

			return GetParentName(LabelCount - domainName.LabelCount).Equals(domainName);
		}

		internal byte[] GetNSec3Hash(NSec3HashAlgorithm algorithm, int iterations, byte[] salt)
		{
			IDigest digest;

			switch (algorithm)
			{
				case NSec3HashAlgorithm.Sha1:
					digest = new Sha1Digest();
					break;

				default:
					throw new NotSupportedException();
			}

			var buffer = new byte[Math.Max(MaximumRecordDataLength + 1, digest.GetDigestSize()) + salt.Length];

			var length = 0;

			DnsMessageBase.EncodeDomainName(buffer, ref length, this, null, true);

			for (var i = 0; i <= iterations; i++)
			{
				DnsMessageBase.EncodeByteArray(buffer, ref length, salt);

				digest.BlockUpdate(buffer, 0, length);

				digest.DoFinal(buffer, 0);
				length = digest.GetDigestSize();
			}

			var res = new byte[length];
			Buffer.BlockCopy(buffer, 0, res, 0, length);

			return res;
		}

		internal DomainName GetNSec3HashName(NSec3HashAlgorithm algorithm, int iterations, byte[] salt, DomainName zoneApex)
		{
			return new DomainName(GetNSec3Hash(algorithm, iterations, salt).ToBase32HexString(), zoneApex);
		}

		internal static DomainName ParseFromMasterfile(string name, DomainName origin)
		{
			if (String.IsNullOrEmpty(name))
				throw new ArgumentException("Name must be provided", nameof(name));

			var parsed = Parse(name);

			return name.EndsWith(".") ? parsed : parsed + origin;
		}

		/// <summary>
		///   Parses the string representation of a domain name
		/// </summary>
		/// <param name="s">The string representation of the domain name to parse</param>
		/// <returns>A new instance of the DomainName class</returns>
		public static DomainName Parse(string s)
		{
			if (TryParse(s, out var res))
				return res!;

			throw new ArgumentException("Domain name could not be parsed", nameof(s));
		}

		/// <summary>
		///   Parses the string representation of a domain name
		/// </summary>
		/// <param name="s">The string representation of the domain name to parse</param>
		/// <param name="name">
		///   When this method returns, contains a DomainName instance representing s or null, if s could not be
		///   parsed
		/// </param>
		/// <returns>true, if s was parsed successfully; otherwise, false</returns>
		public static bool TryParse(string s, out DomainName? name)
		{
			if (String.IsNullOrEmpty(s))
			{
				name = null;
				return false;
			}

			if (s == ".")
			{
				name = Root;
				return true;
			}

			List<string> labels = new List<string>();

			int lastOffset = 0;
			int nextOffset;

			while ((nextOffset = s.IndexOfWithQuoting('.', lastOffset)) != -1)
			{
				if (TryParseLabel(s.Substring(lastOffset, nextOffset - lastOffset), out string? label))
				{
					labels.Add(label!);
					lastOffset = nextOffset + 1;
				}
				else
				{
					name = null;
					return false;
				}
			}

			if (s.Length == lastOffset)
			{
				// empty label --> name ends with dot
			}
			else if (TryParseLabel(s.Substring(lastOffset, s.Length - lastOffset), out string? label))
			{
				labels.Add(label!);
			}
			else
			{
				name = default;
				return false;
			}

			if (labels.Sum(l => l.Length) + labels.Count > 255 || labels.Any(l => l.Length == 0))
			{
				name = null;
				return false;
			}

			name = new DomainName(labels.ToArray());
			return true;
		}

		private static readonly IdnMapping _idnParser = new() { UseStd3AsciiRules = true };

		private static bool TryParseLabel(string s, out string? label)
		{
			try
			{
				s = s.FromMasterfileLabelRepresentation();

				if (s.Length > 63)
				{
					label = null;
					return false;
				}

				if (s.Any(c => c > 127))
				{
					s = _idnParser.GetAscii(s);
				}

				label = s;
				return true;
			}
			catch
			{
				label = null;
				return false;
			}
		}

		/// <summary>
		///   Returns the string representation of the domain name
		/// </summary>
		/// <returns>The string representation of the domain name</returns>
		public override string ToString()
		{
			return ToString(true);
		}

		private string? _toString;

		public string ToString(bool asAbsoluteFqdn)
		{
			_toString ??= String.Join(".", _labels.Select(x => x.ToMasterfileLabelRepresentation(true)));

			return (asAbsoluteFqdn ? _toString + "." : _toString);
		}

		private int? _hashCode;

		/// <summary>
		///   Returns the hash code for this domain name
		/// </summary>
		/// <returns>The hash code for this domain name</returns>
		[SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
		public override int GetHashCode()
		{
			if (_hashCode.HasValue)
				return _hashCode.Value;

			int hash = LabelCount;

			for (int i = 0; i < LabelCount; i++)
			{
				unchecked
				{
					hash = hash * 17 + _labels[i].ToLowerInvariant().GetHashCode();
				}
			}

			return (_hashCode = hash).Value;
		}

		/// <summary>
		///   Concatinates two names
		/// </summary>
		/// <param name="name1">The left name</param>
		/// <param name="name2">The right name</param>
		/// <returns>A new domain name</returns>
		public static DomainName operator +(DomainName name1, DomainName name2)
		{
			string[] newLabels = new string[name1.LabelCount + name2.LabelCount];

			Array.Copy(name1._labels, newLabels, name1.LabelCount);
			Array.Copy(name2._labels, 0, newLabels, name1.LabelCount, name2.LabelCount);

			return new DomainName(newLabels);
		}

		/// <summary>
		///   Checks, whether two names are identical (case sensitive)
		/// </summary>
		/// <param name="name1">The first name</param>
		/// <param name="name2">The second name</param>
		/// <returns>true, if the names are identical</returns>
		public static bool operator ==(DomainName? name1, DomainName? name2)
		{
			if (ReferenceEquals(name1, name2))
				return true;

			if (ReferenceEquals(name1, null))
				return false;

			return name1.Equals(name2, false);
		}

		/// <summary>
		///   Checks, whether two names are not identical (case sensitive)
		/// </summary>
		/// <param name="name1">The first name</param>
		/// <param name="name2">The second name</param>
		/// <returns>true, if the names are not identical</returns>
		public static bool operator !=(DomainName? name1, DomainName? name2)
		{
			return !(name1 == name2);
		}

		/// <summary>
		///   Checks, whether this name is equal to an other object (case insensitive)
		/// </summary>
		/// <param name="obj">The other object</param>
		/// <returns>true, if the names are equal</returns>
		public override bool Equals(object? obj)
		{
			return Equals(obj as DomainName);
		}

		/// <summary>
		///   Checks, whether this name is equal to an other name (case insensitive)
		/// </summary>
		/// <param name="other">The other name</param>
		/// <returns>true, if the names are equal</returns>
		public bool Equals(DomainName? other)
		{
			return Equals(other, true);
		}

		/// <summary>
		///   Checks, whether this name is equal to an other name
		/// </summary>
		/// <param name="other">The other name</param>
		/// <param name="ignoreCase">true, if the case should ignored on checking</param>
		/// <returns>true, if the names are equal</returns>
		public bool Equals(DomainName? other, bool ignoreCase)
		{
			if (ReferenceEquals(other, null))
				return false;

			if (LabelCount != other.LabelCount)
				return false;

			if (_hashCode.HasValue && other._hashCode.HasValue && (_hashCode != other._hashCode))
				return false;

			StringComparison comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

			for (int i = 0; i < LabelCount; i++)
			{
				if (!String.Equals(_labels[i], other._labels[i], comparison))
					return false;
			}

			return true;
		}

		/// <summary>
		///   Compares the current instance with another name and returns an integer that indicates whether the current instance
		///   precedes, follows, or occurs in the same position in the sort order as the other name.
		/// </summary>
		/// <param name="other">A name to compare with this instance.</param>
		/// <returns>A value that indicates the relative order of the objects being compared.</returns>
		public int CompareTo(DomainName? other)
		{
			if (ReferenceEquals(other, null))
				return 1;

			for (int i = 1; i <= Math.Min(LabelCount, other.LabelCount); i++)
			{
				int labelCompare = String.Compare(Labels[LabelCount - i].ToLowerInvariant(), other.Labels[other.LabelCount - i].ToLowerInvariant(), StringComparison.Ordinal);

				if (labelCompare != 0)
					return labelCompare;
			}

			return LabelCount.CompareTo(other.LabelCount);
		}
	}
}