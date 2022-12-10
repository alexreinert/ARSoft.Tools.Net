#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Type of algorithm
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public enum TSigAlgorithm
	{
		/// <summary>
		///   Unknown
		/// </summary>
		Unknown,

		/// <summary>
		///   <para>MD5</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2845.html">RFC 2845</a>.
		///   </para>
		/// </summary>
		Md5,

		/// <summary>
		///   <para>SHA-1</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4635.html">RFC 4635</a>.
		///   </para>
		/// </summary>
		Sha1,

		/// <summary>
		///   <para>SHA-1</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8945.html">RFC 8945</a>.
		///   </para>
		/// </summary>
		Sha224,

		/// <summary>
		///   <para>SHA-256</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4635.html">RFC 4635</a>.
		///   </para>
		/// </summary>
		Sha256,

		/// <summary>
		///   <para>SHA-256 with truncation</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8945.html">RFC 8945</a>.
		///   </para>
		/// </summary>
		Sha256_128,

		/// <summary>
		///   <para>SHA-384</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4635.html">RFC 4635</a>.
		///   </para>
		/// </summary>
		Sha384,

		/// <summary>
		///   <para>SHA-384 with truncation</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8945.html">RFC 8945</a>.
		///   </para>
		/// </summary>
		Sha384_192,

		/// <summary>
		///   <para>SHA-512</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4635.html">RFC 4635</a>.
		///   </para>
		/// </summary>
		Sha512,

		/// <summary>
		///   <para>SHA-512 with truncation</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8945.html">RFC 8945</a>.
		///   </para>
		/// </summary>
		Sha512_256,
	}
}