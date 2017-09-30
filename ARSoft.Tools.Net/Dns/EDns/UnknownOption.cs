#region Copyright and License
// Copyright 2010 Alexander Reinert
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
	public class UnknownOption : EDnsOptionBase
	{
		public byte[] Data { get; set; }

		public UnknownOption(EDnsOptionType type)
			: base(type) {}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Data = new byte[length];
			Buffer.BlockCopy(resultData, startPosition, Data, 0, length);
		}

		internal override ushort DataLength
		{
			get { return (ushort) ((Data == null) ? 0 : Data.Length); }
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