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
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides options to be used in <see cref="DnsClient">DNS client</see> for resolving queries
	/// </summary>
	public class DnsQueryOptions
	{
		/// <summary>
		///   <para>Gets or sets the recursion desired (RD) flag</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		public bool IsRecursionDesired { get; set; }

		/// <summary>
		///   <para>Gets or sets the checking disabled (CD) flag</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4035">RFC 4035</see>
		///   </para>
		/// </summary>
		public bool IsCheckingDisabled { get; set; }

		/// <summary>
		///   Enables or disables EDNS
		/// </summary>
		public bool IsEDnsEnabled
		{
			get { return (EDnsOptions != null); }
			set
			{
				if (value && (EDnsOptions == null))
				{
					EDnsOptions = new OptRecord();
				}
				else if (!value)
				{
					EDnsOptions = null;
				}
			}
		}

		/// <summary>
		///   Gets or set the OptRecord for the EDNS options
		/// </summary>
		public OptRecord EDnsOptions { get; set; }

		/// <summary>
		///   <para>Gets or sets the DNSSEC answer OK (DO) flag</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4035">RFC 4035</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3225">RFC 3225</see>
		///   </para>
		/// </summary>
		public bool IsDnsSecOk
		{
			get
			{
				OptRecord ednsOptions = EDnsOptions;
				return (ednsOptions != null) && ednsOptions.IsDnsSecOk;
			}
			set
			{
				OptRecord ednsOptions = EDnsOptions;
				if (ednsOptions == null)
				{
					if (value)
					{
						throw new ArgumentOutOfRangeException(nameof(value), "Setting DO flag is allowed in edns messages only");
					}
				}
				else
				{
					ednsOptions.IsDnsSecOk = value;
				}
			}
		}
	}
}