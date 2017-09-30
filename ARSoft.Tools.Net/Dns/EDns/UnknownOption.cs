using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class UnknownOption : EDnsOptionBase
	{
		public byte[] Data { get; set; }

		public UnknownOption(EDnsOptionType type)
			: base(type)
		{
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Data = new byte[length];
			Buffer.BlockCopy(resultData, startPosition, Data, 0, length);
		}

		internal override ushort DataLength
		{
			get { return (ushort)((Data == null) ? 0 : Data.Length); }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			if ((Data != null) && (Data.Length != 0))
			{
				Buffer.BlockCopy(Data, 0, messageData, currentPosition, Data.Length);
				currentPosition += Data.Length;
			}
		}
	}
}
