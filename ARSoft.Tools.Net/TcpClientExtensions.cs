#region Copyright and License
// Copyright 2010..2016 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
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
using System.Threading.Tasks;

namespace ARSoft.Tools.Net
{
	internal static class TcpClientExtensions
	{
		public static bool TryConnect(this TcpClient tcpClient, IPEndPoint endPoint, int timeout)
		{
			IAsyncResult ar = tcpClient.BeginConnect(endPoint.Address, endPoint.Port, null, null);
			var wh = ar.AsyncWaitHandle;
			try
			{
				if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeout), false))
				{
					tcpClient.Close();
					return false;
				}

				tcpClient.EndConnect(ar);
				return true;
			}
			finally
			{
				wh.Close();
			}
		}

		public static async Task<bool> TryConnectAsync(this TcpClient tcpClient, IPAddress address, int port, int timeout, CancellationToken token)
		{
			var connectTask = tcpClient.ConnectAsync(address, port);
			var timeoutTask = Task.Delay(timeout, token);

			await Task.WhenAny(connectTask, timeoutTask);

			if (connectTask.IsCompleted)
				return true;

			tcpClient.Close();
			return false;
		}

		public static bool IsConnected(this TcpClient client)
		{
			if (!client.Connected)
				return false;

			if (client.Client.Poll(0, SelectMode.SelectRead))
			{
				if (client.Connected)
				{
					byte[] b = new byte[1];
					try
					{
						if (client.Client.Receive(b, SocketFlags.Peek) == 0)
						{
							return false;
						}
					}
					catch
					{
						return false;
					}
				}
			}

			return true;
		}
	}
}