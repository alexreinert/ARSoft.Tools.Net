#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   DNSSEC algorithm type
	/// </summary>
	public enum NSec3HashAlgorithm : byte
	{
		/// <summary>
		///   <para>RSA MD5</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
		///   </para>
		/// </summary>
		Sha1 = 1,
	}

	internal static class NSec3HashAlgorithmHelper
	{
		public static bool IsSupported(this NSec3HashAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case NSec3HashAlgorithm.Sha1:
					return true;

				default:
					return false;
			}
		}

		public static int GetPriority(this NSec3HashAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case NSec3HashAlgorithm.Sha1:
					return 1;

				default:
					throw new NotSupportedException();
			}
		}
	}
}