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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	internal class DnsAsyncState : IAsyncResult
	{
		internal List<IPAddress> Servers;
		internal int ServerIndex;
		internal byte[] QueryData;
		internal int QueryLength;

		internal DnsServer.SelectTsigKey TSigKeySelector;
		internal byte[] TSigOriginalMac;

		internal DnsMessage Response;

		internal Timer Timer;
		internal bool TimedOut;

		internal UdpClient UdpClient;
		internal IPEndPoint UdpEndpoint;

		internal TcpClient TcpClient;
		internal NetworkStream TcpStream;
		internal byte[] TcpBuffer;

		internal AsyncCallback UserCallback;
		public object AsyncState { get; internal set; }
		public bool IsCompleted { get; private set; }

		public bool CompletedSynchronously
		{
			get { return false; }
		}

		private ManualResetEvent _waitHandle;

		public WaitHandle AsyncWaitHandle
		{
			get { return _waitHandle ?? (_waitHandle = new ManualResetEvent(IsCompleted)); }
		}

		internal void SetCompleted()
		{
			QueryData = null;

			if (Timer != null)
			{
				Timer.Dispose();
				Timer = null;
			}


			IsCompleted = true;
			if (_waitHandle != null)
				_waitHandle.Set();

			if (UserCallback != null)
				UserCallback(this);
		}
	}
}