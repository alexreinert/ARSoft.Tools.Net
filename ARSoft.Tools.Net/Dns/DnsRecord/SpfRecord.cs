using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class SpfRecord : TxtRecord
	{
		internal SpfRecord() { }

		public SpfRecord(string name, int timeToLive, string textData)
			: base(name, RecordType.Spf, RecordClass.INet, timeToLive, textData)
		{
		}
	}
}
