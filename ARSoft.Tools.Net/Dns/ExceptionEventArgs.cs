using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class ExceptionEventArgs : EventArgs
	{
		public Exception Exception { get; set; }

		public ExceptionEventArgs(Exception exception)
			: base()
		{
			Exception = exception;
		}
	}
}
