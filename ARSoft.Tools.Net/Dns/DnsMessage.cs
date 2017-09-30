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
	public class DnsMessage : DnsMessageBase
	{
		#region Header
		/// <summary>
		/// Gets or sets the autoritive answer (AA) flag
		/// </summary>
		public bool IsAuthoritiveAnswer
		{
			get { return (_flags & 0x0400) != 0; }
			set
			{
				if (value)
				{
					_flags |= 0x0400;
				}
				else
				{
					_flags &= 0xfbff;
				}
			}
		}

		/// <summary>
		/// Gets or sets the truncated (TC) flag
		/// </summary>
		public bool IsTruncated
		{
			get { return (_flags & 0x0200) != 0; }
			set
			{
				if (value)
				{
					_flags |= 0x0200;
				}
				else
				{
					_flags &= 0xfdff;
				}
			}
		}

		/// <summary>
		/// Gets or sets the recursion desired (RD) flag
		/// </summary>
		public bool IsRecursionDesired
		{
			get { return (_flags & 0x0100) != 0; }
			set
			{
				if (value)
				{
					_flags |= 0x0100;
				}
				else
				{
					_flags &= 0xfeff;
				}
			}
		}

		/// <summary>
		/// Gets or sets the recursion allowed (RA) flag
		/// </summary>
		public bool IsRecursionAllowed
		{
			get { return (_flags & 0x0080) != 0; }
			set
			{
				if (value)
				{
					_flags |= 0x0080;
				}
				else
				{
					_flags &= 0xff7f;
				}
			}
		}

		/// <summary>
		/// Gets or sets the authentic data (AD) flag
		/// </summary>
		public bool IsAuthenticData
		{
			get { return (_flags & 0x0020) != 0; }
			set
			{
				if (value)
				{
					_flags |= 0x0020;
				}
				else
				{
					_flags &= 0xffdf;
				}
			}
		}

		/// <summary>
		/// Gets or sets the checking disabled (CD) flag
		/// </summary>
		public bool IsCheckingDisabled
		{
			get { return (_flags & 0x0010) != 0; }
			set
			{
				if (value)
				{
					_flags |= 0x0010;
				}
				else
				{
					_flags &= 0xffef;
				}
			}
		}
		#endregion

		/// <summary>
		/// Gets or sets the entries in the question section
		/// </summary>
		public List<DnsQuestion> Questions
		{
			get { return _questions; }
			set { _questions = (value ?? new List<DnsQuestion>()); }
		}

		/// <summary>
		/// Gets or sets the entries in the answer records section
		/// </summary>
		public List<DnsRecordBase> AnswerRecords
		{
			get { return _answerRecords; }
			set { _answerRecords = (value ?? new List<DnsRecordBase>()); }
		}

		/// <summary>
		/// Gets or sets the entries in the authority records section
		/// </summary>
		public List<DnsRecordBase> AuthorityRecords
		{
			get { return _authorityRecords; }
			set { _authorityRecords = (value ?? new List<DnsRecordBase>()); }
		}

		internal override bool IsTcpUsingRequested
		{
			get { return (Questions.Count > 0) && ((Questions[0].RecordType == RecordType.Axfr) || (Questions[0].RecordType == RecordType.Ixfr)); }
		}

		internal override bool IsTcpResendingRequested
		{
			get { return IsTruncated; }
		}
	}
}