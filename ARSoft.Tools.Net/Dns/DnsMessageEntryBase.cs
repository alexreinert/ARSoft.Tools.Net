using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class DnsMessageEntryBase
	{
		public string Name { get; internal set; }
		public RecordType RecordType { get; internal set; }
		public RecordClass RecordClass { get; internal set; }

		internal abstract int MaximumLength { get; }
		internal abstract void Encode(byte[] destination, ref int startPosition, Dictionary<string, ushort> domainNames);

		public override string ToString()
		{
			return Name + " " + RecordType + " " + RecordClass;
		}
	}
}
