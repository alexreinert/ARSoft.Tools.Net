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
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Operation code of a dns query
	/// </summary>
	public enum OperationCode : ushort
	{
		/// <summary>
		///   <para>Normal query</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Query = 0,

		/// <summary>
		///   <para>Inverse query</para>
		///   <para>
		///     Obsoleted by
		///     <a href="https://www.rfc-editor.org/rfc/rfc3425.html">RFC 3425</a>.
		///   </para>
		/// </summary>
		[Obsolete] InverseQuery = 1,

		/// <summary>
		///   <para>Server status request</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>.
		///   </para>
		/// </summary>
		Status = 2,

		/// <summary>
		///   <para>Notify of zone change</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc1996.html">RFC 1996</a>.
		///   </para>
		/// </summary>
		Notify = 4,

		/// <summary>
		///   <para>Dynamic update</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc2136.html">RFC 2136</a>.
		///   </para>
		/// </summary>
		Update = 5,
	}
}