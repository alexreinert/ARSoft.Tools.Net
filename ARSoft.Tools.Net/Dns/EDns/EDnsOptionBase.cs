using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class EDnsOptionBase
	{
		public EDnsOptionType Type { get; internal set; }

		internal EDnsOptionBase(EDnsOptionType optionType)
		{
			Type = optionType;
		}

		internal abstract void ParseData(byte[] resultData, int startPosition, int length);
		internal abstract ushort DataLength { get; }
		internal abstract void EncodeData(byte[] messageData, ref int currentPosition);
	}
}
