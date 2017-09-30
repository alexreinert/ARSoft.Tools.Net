using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	internal class DnsAsyncState : IAsyncResult
	{
		internal IEnumerator<IPAddress> ServerEnumerator;
		internal byte[] QueryData;
		internal int QueryLength;

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
		public bool CompletedSynchronously { get { return false; } }

		private ManualResetEvent _waitHandle = null;
		public System.Threading.WaitHandle AsyncWaitHandle
		{
			get
			{
				if (_waitHandle == null)
				{
					_waitHandle = new ManualResetEvent(IsCompleted);
				}

				return _waitHandle;
			}
		}

		internal void SetCompleted()
		{
			if (ServerEnumerator != null)
			{
				ServerEnumerator.Dispose();
				ServerEnumerator = null;
			}

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