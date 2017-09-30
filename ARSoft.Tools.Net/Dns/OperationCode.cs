using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public enum OperationCode : ushort
	{
		Query = 0x0000,
		InverseQuery = 0x0800,
		Status = 0x1000,
		Notify = 0x2000,
		Update = 0x2800,
	}
}
