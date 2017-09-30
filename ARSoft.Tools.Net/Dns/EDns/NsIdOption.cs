using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class NsIdOption : EDnsOptionBase
	{
		public byte[] Payload { get; set; }

		public NsIdOption()
			: base(EDnsOptionType.NsId)
		{
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Payload = new byte[length];
			Buffer.BlockCopy(resultData, startPosition, Payload, 0, length);
		}

		internal override ushort DataLength
		{
			get { return (ushort)((Payload == null) ? 0 : Payload.Length); }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			if ((Payload != null) && (Payload.Length != 0))
			{
				Buffer.BlockCopy(Payload, 0, messageData, currentPosition, Payload.Length);
				currentPosition += Payload.Length;
			}
		}
	}
}
