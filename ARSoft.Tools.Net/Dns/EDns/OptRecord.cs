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
	///   <para>OPT record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc2671.html">RFC 2671</a>.
	///   </para>
	/// </summary>
	public class OptRecord : DnsRecordBase
	{
		/// <summary>
		///   Gets or set the sender's UDP payload size
		/// </summary>
		public ushort UdpPayloadSize
		{
			get { return (ushort) RecordClass; }
			set { RecordClass = (RecordClass) value; }
		}

		/// <summary>
		///   Gets or sets the high bits of return code (EXTENDED-RCODE)
		/// </summary>
		public ReturnCode ExtendedReturnCode
		{
			get { return (ReturnCode) ((TimeToLive & 0xff000000) >> 20); }
			set
			{
				int clearedTtl = (TimeToLive & 0x00ffffff);
				TimeToLive = (clearedTtl | ((int) value << 20));
			}
		}

		/// <summary>
		///   Gets or set the EDNS version
		/// </summary>
		public byte Version
		{
			get { return (byte) ((TimeToLive & 0x00ff0000) >> 16); }
			set
			{
				int clearedTtl = (int) ((uint) TimeToLive & 0xff00ffff);
				TimeToLive = clearedTtl | (value << 16);
			}
		}

		/// <summary>
		///   <para>Gets or sets the DNSSEC OK (DO) flag</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc4035.html">RFC 4035</a>.
		///     and
		///     <a href="https://www.rfc-editor.org/rfc/rfc3225.html">RFC 3225</a>.
		///   </para>
		/// </summary>
		public bool IsDnsSecOk
		{
			get { return (TimeToLive & 0x8000) != 0; }
			set
			{
				if (value)
				{
					TimeToLive |= 0x8000;
				}
				else
				{
					TimeToLive &= 0x7fff;
				}
			}
		}

		/// <summary>
		///   Gets or set additional EDNS options
		/// </summary>
		public List<EDnsOptionBase> Options { get; private set; }

		/// <summary>
		///   Creates a new instance of the OptRecord
		/// </summary>
		/// <param name="udpPayloadSize">The sender's UDP payload size</param>
		/// <param name="options">Additional EDNS options</param>
		public OptRecord(ushort udpPayloadSize = 4096, params EDnsOptionBase[] options)
			: base(DomainName.Root, RecordType.Opt, unchecked((RecordClass) udpPayloadSize), 0)
		{
			Options = options.ToList();
		}

		internal OptRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
			: base(name, recordType, recordClass, timeToLive)
		{
			int endPosition = currentPosition + length;

			Options = new List<EDnsOptionBase>();
			while (currentPosition < endPosition)
			{
				EDnsOptionType type = (EDnsOptionType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
				ushort dataLength = DnsMessageBase.ParseUShort(resultData, ref currentPosition);

				EDnsOptionBase option;

				switch (type)
				{
					case EDnsOptionType.LongLivedQuery:
						option = new LongLivedQueryOption(resultData, currentPosition);
						break;

					case EDnsOptionType.UpdateLease:
						option = new UpdateLeaseOption(resultData, currentPosition);
						break;

					case EDnsOptionType.NsId:
						option = new NsIdOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.Owner:
						option = new OwnerOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.DnssecAlgorithmUnderstood:
						option = new DnssecAlgorithmUnderstoodOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.DsHashUnderstood:
						option = new DsHashUnderstoodOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.Nsec3HashUnderstood:
						option = new Nsec3HashUnderstoodOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.ClientSubnet:
						option = new ClientSubnetOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.Expire:
						option = new ExpireOption(resultData, currentPosition, dataLength);
						break;

					case EDnsOptionType.Cookie:
						option = new CookieOption(resultData, currentPosition, dataLength);
						break;

					default:
						option = new UnknownOption(type, resultData, currentPosition, dataLength);
						break;
				}

				Options.Add(option);
				currentPosition += dataLength;
			}
		}

		internal OptRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
			: base(name, recordType, recordClass, timeToLive)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		///   Returns the textual representation of the OptRecord
		/// </summary>
		/// <returns> The textual representation </returns>
		public override string ToString()
		{
			return RecordDataToString();
		}

		internal override string RecordDataToString()
		{
			string flags = IsDnsSecOk ? "DO" : "";
			return String.Format("; EDNS version: {0}; flags: {1}; udp: {2}", Version, flags, UdpPayloadSize);
		}

		protected internal override int MaximumRecordDataLength
		{
			get
			{
				if ((Options == null) || (Options.Count == 0))
				{
					return 0;
				}
				else
				{
					return Options.Sum(option => option.DataLength + 4);
				}
			}
		}

		protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
		{
			if ((Options != null) && (Options.Count != 0))
			{
				foreach (EDnsOptionBase option in Options)
				{
					DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) option.Type);
					DnsMessageBase.EncodeUShort(messageData, ref currentPosition, option.DataLength);
					option.EncodeData(messageData, ref currentPosition);
				}
			}
		}
	}
}