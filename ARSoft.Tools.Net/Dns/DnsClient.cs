#region Copyright and License
// Copyright 2010..2012 Alexander Reinert
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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using ARSoft.Tools.Net.Dns.DynamicUpdate;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides a client for querying dns records
	/// </summary>
	public class DnsClient
	{
		private const int _DNS_PORT = 53;
		private readonly List<IPAddress> _dnsServers;

		/// <summary>
		///   Milliseconds after which a query times out.
		/// </summary>
		public int QueryTimeout { get; set; }

		/// <summary>
		///   Returns a default instance of the DnsClient, which uses the configured dns servers of the executing computer and a query timeout of 10 seconds.
		/// </summary>
		public static DnsClient Default { get; private set; }

		static DnsClient()
		{
			Default = new DnsClient(GetDnsServers(), 10000);
		}

		/// <summary>
		///   Provides a new instance with custom dns server and query timeout
		/// </summary>
		/// <param name="dnsServers"> The IPAddress of the dns server to use </param>
		/// <param name="queryTimeout"> Query timeout in milliseconds </param>
		public DnsClient(IPAddress dnsServers, int queryTimeout)
		{
			_dnsServers = new List<IPAddress>() { dnsServers };
			QueryTimeout = queryTimeout;
		}

		/// <summary>
		///   Provides a new instance with custom dns servers and query timeout
		/// </summary>
		/// <param name="dnsServers"> The IPAddresses of the dns servers to use </param>
		/// <param name="queryTimeout"> Query timeout in milliseconds </param>
		public DnsClient(List<IPAddress> dnsServers, int queryTimeout)
		{
			_dnsServers = dnsServers;
			QueryTimeout = queryTimeout;
		}

		/// <summary>
		///   Queries a dns server for address records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage Resolve(string name)
		{
			return Resolve(name, RecordType.A, RecordClass.INet);
		}

		/// <summary>
		///   Queries a dns server for specified records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Recordtype the should be queried </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage Resolve(string name, RecordType recordType)
		{
			return Resolve(name, recordType, RecordClass.INet);
		}

		/// <summary>
		///   Queries a dns server for specified records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage Resolve(string name, RecordType recordType, RecordClass recordClass)
		{
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name must be provided", "name");
			}

			DnsMessage message = new DnsMessage() { IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true };
			message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

			return SendMessage(message);
		}

		/// <summary>
		///   Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="requestCallback"> An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete. </param>
		/// <param name="state"> A user-defined object that contains information about the receive operation. This object is passed to the <paramref
		///    name="requestCallback" /> delegate when the operation is complete. </param>
		/// <returns> An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive. </returns>
		public IAsyncResult BeginResolve(string name, AsyncCallback requestCallback, object state)
		{
			return BeginResolve(name, RecordType.A, RecordClass.INet, requestCallback, state);
		}

		/// <summary>
		///   Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="requestCallback"> An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete. </param>
		/// <param name="state"> A user-defined object that contains information about the receive operation. This object is passed to the <paramref
		///    name="requestCallback" /> delegate when the operation is complete. </param>
		/// <returns> An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive. </returns>
		public IAsyncResult BeginResolve(string name, RecordType recordType, AsyncCallback requestCallback, object state)
		{
			return BeginResolve(name, recordType, RecordClass.INet, requestCallback, state);
		}

		/// <summary>
		///   Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <param name="requestCallback"> An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete. </param>
		/// <param name="state"> A user-defined object that contains information about the receive operation. This object is passed to the <paramref
		///    name="requestCallback" /> delegate when the operation is complete. </param>
		/// <returns> An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive. </returns>
		public IAsyncResult BeginResolve(string name, RecordType recordType, RecordClass recordClass, AsyncCallback requestCallback, object state)
		{
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name must be provided", "name");
			}

			DnsMessage message = new DnsMessage() { IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true };
			message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

			return BeginSendMessage(message, requestCallback, state);
		}

		/// <summary>
		///   Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar"> An <see cref="System.IAsyncResult" /> object returned by a call to <see
		///    cref="ARSoft.Tools.Net.Dns.DnsClient.BeginResolve" /> . </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage EndResolve(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar;
			return state.Response;
		}

		/// <summary>
		///   Send a custom message to the dns server and returns the answer.
		/// </summary>
		/// <param name="message"> Message, that should be send to the dns server </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage SendMessage(DnsMessage message)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if ((message.Questions == null) || (message.Questions.Count == 0))
				throw new ArgumentException("At least one question must be provided", "message");

			return SendMessage<DnsMessage>(message);
		}

		/// <summary>
		///   Send an dynamic update to the dns server and returns the answer.
		/// </summary>
		/// <param name="message"> Update, that should be send to the dns server </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsUpdateMessage SendUpdate(DnsUpdateMessage message)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if (String.IsNullOrEmpty(message.ZoneName))
				throw new ArgumentException("Zone name must be provided", "message");

			return SendMessage(message);
		}

		private TMessage SendMessage<TMessage>(TMessage message)
			where TMessage : DnsMessageBase, new()
		{
			if (message.TransactionID == 0)
			{
				message.TransactionID = (ushort) new Random().Next(0xffff);
			}

			byte[] messageData;
			int messageLength = message.Encode(false, out messageData);

			bool sendByTcp = ((messageLength > 512) || message.IsTcpUsingRequested);

			for (int i = 0; i < _dnsServers.Count; i++)
			{
				IPAddress nameServer = _dnsServers[i];

				byte[] resultData = sendByTcp ? QueryByTcp(nameServer, messageData, messageLength) : QueryByUdp(nameServer, messageData, messageLength);

				if (resultData != null)
				{
					DnsServer.SelectTsigKey tsigKeySelector;
					byte[] tsigOriginalMac;

					if (message.TSigOptions != null)
					{
						tsigKeySelector = (n, a) => message.TSigOptions.KeyData;
						tsigOriginalMac = message.TSigOptions.Mac;
					}
					else
					{
						tsigKeySelector = null;
						tsigOriginalMac = null;
					}

					TMessage result = new TMessage();
					result.Parse(resultData, false, tsigKeySelector, tsigOriginalMac);

					if ((result.ReturnCode == ReturnCode.ServerFailure) && (i != _dnsServers.Count - 1))
					{
						continue;
					}

					if (result.IsTcpResendingRequested)
					{
						resultData = QueryByTcp(nameServer, messageData, messageLength);
						if (resultData != null)
						{
							TMessage tcpResult = new TMessage();
							tcpResult.Parse(resultData, false, tsigKeySelector, tsigOriginalMac);

							if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
							{
								if (i != _dnsServers.Count - 1)
								{
									continue;
								}
							}
							else
							{
								result = tcpResult;
							}
						}
					}

					return result;
				}
			}

			return null;
		}

		private byte[] QueryByUdp(IPAddress nameServer, byte[] messageData, int messageLength)
		{
			IPEndPoint endPoint = new IPEndPoint(nameServer, _DNS_PORT);

			using (UdpClient udpClient = new UdpClient(nameServer.AddressFamily))
			{
				try
				{
					udpClient.Client.ReceiveTimeout = QueryTimeout;
					udpClient.Connect(endPoint);
					udpClient.Send(messageData, messageLength);
					return udpClient.Receive(ref endPoint);
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);
					return null;
				}
			}
		}

		private byte[] QueryByTcp(IPAddress nameServer, byte[] messageData, int messageLength)
		{
			IPEndPoint endPoint = new IPEndPoint(nameServer, _DNS_PORT);

			using (TcpClient tcpClient = new TcpClient(nameServer.AddressFamily))
			{
				try
				{
					tcpClient.ReceiveTimeout = QueryTimeout;
					tcpClient.SendTimeout = QueryTimeout;
					tcpClient.Connect(endPoint);

					byte[] resultData;
					using (NetworkStream tcpStream = tcpClient.GetStream())
					{
						int tmp = 0;

						byte[] lengthBuffer = new byte[2];
						DnsMessageBase.EncodeUShort(lengthBuffer, ref tmp, (ushort) messageLength);

						tcpStream.Write(lengthBuffer, 0, 2);
						tcpStream.Write(messageData, 0, messageLength);

						lengthBuffer[0] = (byte) tcpStream.ReadByte();
						lengthBuffer[1] = (byte) tcpStream.ReadByte();

						tmp = 0;
						int length = DnsMessageBase.ParseUShort(lengthBuffer, ref tmp);

						resultData = new byte[length];

						int readBytes = 0;

						while (readBytes < length)
						{
							readBytes += tcpStream.Read(resultData, readBytes, length - readBytes);
						}
					}

					return resultData;
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);
					return null;
				}
			}
		}

		/// <summary>
		///   Send a custom message to the dns server and returns the answer asynchronously.
		/// </summary>
		/// <param name="message"> Message, that should be send to the dns server </param>
		/// <param name="requestCallback"> An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete. </param>
		/// <param name="state"> A user-defined object that contains information about the receive operation. This object is passed to the <paramref
		///    name="requestCallback" /> delegate when the operation is complete. </param>
		/// <returns> An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive. </returns>
		public IAsyncResult BeginSendMessage(DnsMessage message, AsyncCallback requestCallback, object state)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if ((message.Questions == null) || (message.Questions.Count == 0))
				throw new ArgumentException("At least one question must be provided", "message");

			if (message.TransactionID == 0)
			{
				message.TransactionID = (ushort) new Random().Next(0xffff);
			}

			byte[] queryData;
			int queryLength = message.Encode(false, out queryData);

			DnsAsyncState asyncResult = new DnsAsyncState() { QueryData = queryData, QueryLength = queryLength, UserCallback = requestCallback, AsyncState = state, Servers = _dnsServers, ServerIndex = 0 };
			if (message.TSigOptions != null)
			{
				asyncResult.TSigKeySelector = (a, n) => message.TSigOptions.KeyData;
				asyncResult.TSigOriginalMac = message.TSigOptions.Mac;
			}

			bool sendByTcp = ((queryLength > 512) || (message.Questions[0].RecordType == RecordType.Axfr) || (message.Questions[0].RecordType == RecordType.Ixfr));

			if (sendByTcp)
			{
				TcpBeginConnect(asyncResult);
			}
			else
			{
				UdpBeginSend(asyncResult);
			}

			return asyncResult;
		}

		/// <summary>
		///   Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar"> An <see cref="System.IAsyncResult" /> object returned by a call to <see
		///    cref="ARSoft.Tools.Net.Dns.DnsClient.BeginSendMessage" /> . </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage EndSendMessage(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar;
			return state.Response;
		}

		#region Event handling async udp query
		private void UdpBeginSend(DnsAsyncState state)
		{
			if (state.ServerIndex == state.Servers.Count)
			{
				state.Response = null;
				state.UdpClient = null;
				state.UdpEndpoint = null;
				state.SetCompleted();
				return;
			}

			state.UdpEndpoint = new IPEndPoint(state.Servers[state.ServerIndex], _DNS_PORT);

			state.UdpClient = new UdpClient(state.UdpEndpoint.AddressFamily);
			state.UdpClient.Connect(state.UdpEndpoint);
			state.TimedOut = false;
			state.TimeRemaining = QueryTimeout;

			IAsyncResult asyncResult = state.UdpClient.BeginSend(state.QueryData, state.QueryLength, UdpSendCompleted, state);
			state.Timer = new Timer(UdpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
		}

		private static void UdpTimedOut(object ar)
		{
			IAsyncResult asyncResult = (IAsyncResult) ar;

			if (!asyncResult.IsCompleted)
			{
				DnsAsyncState state = (DnsAsyncState) asyncResult.AsyncState;
				state.TimedOut = true;
				state.UdpClient.Close();
			}
		}

		private void UdpSendCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				UdpBeginSend(state);
			}
			else
			{
				state.UdpClient.EndSend(ar);

				IAsyncResult asyncResult = state.UdpClient.BeginReceive(UdpReceiveCompleted, state);
				state.Timer = new Timer(UdpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
			}
		}

		private void UdpReceiveCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				UdpBeginSend(state);
			}
			else
			{
				byte[] responseData = state.UdpClient.EndReceive(ar, ref state.UdpEndpoint);

				state.UdpClient.Close();
				state.UdpClient = null;
				state.UdpEndpoint = null;

				state.Response = new DnsMessage();
				state.Response.Parse(responseData, false, state.TSigKeySelector, state.TSigOriginalMac);

				if (state.Response.ReturnCode == ReturnCode.ServerFailure)
				{
					if (state.ServerIndex++ < state.Servers.Count)
					{
						UdpBeginSend(state);
						return;
					}
					else
					{
						state.SetCompleted();
					}
				}
				else
				{
					if (state.Response.IsTruncated)
					{
						TcpBeginConnect(state);
						return;
					}
					else
					{
						state.SetCompleted();
					}
				}
			}
		}
		#endregion

		#region Event handling async tcp query
		private void TcpBeginConnect(DnsAsyncState state)
		{
			if (state.ServerIndex == state.Servers.Count)
			{
				state.Response = null;
				state.TcpStream = null;
				state.TcpClient = null;
				state.SetCompleted();
				return;
			}

			IPAddress server = state.Servers[state.ServerIndex];

			state.TcpClient = new TcpClient(server.AddressFamily);
			state.TimedOut = false;
			state.TimeRemaining = QueryTimeout;

			IAsyncResult asyncResult = state.TcpClient.BeginConnect(server, _DNS_PORT, TcpConnectCompleted, state);
			state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
		}

		private static void TcpTimedOut(object ar)
		{
			IAsyncResult asyncResult = (IAsyncResult) ar;

			if (!asyncResult.IsCompleted)
			{
				DnsAsyncState state = (DnsAsyncState) asyncResult.AsyncState;
				state.TimedOut = true;
				if (state.TcpStream != null)
					state.TcpStream.Close();
				state.TcpClient.Close();
			}
		}

		private void TcpConnectCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpClient.EndConnect(ar);

				state.TcpStream = state.TcpClient.GetStream();

				int tmp = 0;

				state.TcpBuffer = new byte[2];
				DnsMessageBase.EncodeUShort(state.TcpBuffer, ref tmp, (ushort) state.QueryLength);

				IAsyncResult asyncResult = state.TcpStream.BeginWrite(state.TcpBuffer, 0, 2, TcpSendLengthCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
			}
		}

		private void TcpSendLengthCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpStream.EndWrite(ar);

				IAsyncResult asyncResult = state.TcpStream.BeginWrite(state.QueryData, 0, state.QueryLength, TcpSendCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
			}
		}

		private void TcpSendCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpStream.EndWrite(ar);

				state.TcpBytesToReceive = 2;

				IAsyncResult asyncResult = state.TcpStream.BeginRead(state.TcpBuffer, 0, 2, TcpReceiveLengthCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
			}
		}

		private void TcpReceiveLengthCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpBytesToReceive -= state.TcpStream.EndRead(ar);

				if (state.TcpBytesToReceive > 0)
				{
					IAsyncResult asyncResult = state.TcpStream.BeginRead(state.TcpBuffer, 2 - state.TcpBytesToReceive, state.TcpBytesToReceive, TcpReceiveLengthCompleted, state);
					state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
				else
				{
					int tmp = 0;
					int responseLength = DnsMessageBase.ParseUShort(state.TcpBuffer, ref tmp);

					state.TcpBuffer = new byte[responseLength];
					state.TcpBytesToReceive = responseLength;

					IAsyncResult asyncResult = state.TcpStream.BeginRead(state.TcpBuffer, 0, responseLength, TcpReceiveCompleted, state);
					state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
			}
		}

		private void TcpReceiveCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.ServerIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpBytesToReceive -= state.TcpStream.EndRead(ar);

				if (state.TcpBytesToReceive > 0)
				{
					IAsyncResult asyncResult = state.TcpStream.BeginRead(state.TcpBuffer, state.TcpBuffer.Length - state.TcpBytesToReceive, state.TcpBytesToReceive, TcpReceiveCompleted, state);
					state.Timer = new Timer(TcpTimedOut, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
				else
				{
					state.TcpStream.Close();
					state.TcpClient.Close();
					state.TcpStream = null;
					state.TcpClient = null;

					byte[] buffer = state.TcpBuffer;
					state.TcpBuffer = null;

					state.Response = new DnsMessage();
					state.Response.Parse(buffer, false, state.TSigKeySelector, state.TSigOriginalMac);

					if ((state.Response.ReturnCode == ReturnCode.ServerFailure) && (state.ServerIndex++ < state.Servers.Count))
					{
						TcpBeginConnect(state);
						return;
					}
					else
					{
						state.SetCompleted();
					}
				}
			}
		}
		#endregion

		private static List<IPAddress> GetDnsServers()
		{
			List<IPAddress> res = new List<IPAddress>();

			try
			{
				foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
				{
					if ((nic.OperationalStatus == OperationalStatus.Up) && (nic.NetworkInterfaceType != NetworkInterfaceType.Loopback))
					{
						foreach (IPAddress dns in nic.GetIPProperties().DnsAddresses)
						{
							if (!res.Contains(dns))
								res.Add(dns);
						}
					}
				}
			}
			catch (Exception e)
			{
				Trace.TraceError("Configured nameserver couldn't be determined: " + e);
			}

			// try parsing resolv.conf since getting data by NetworkInterface is not supported on non-windows mono
			if ((res.Count == 0) && ((Environment.OSVersion.Platform == PlatformID.Unix) || (Environment.OSVersion.Platform == PlatformID.MacOSX)))
			{
				try
				{
					using (StreamReader reader = File.OpenText("/etc/resolv.conf"))
					{
						string line;
						while ((line = reader.ReadLine()) != null)
						{
							int commentStart = line.IndexOf('#');
							if (commentStart != -1)
							{
								line = line.Substring(0, commentStart);
							}

							string[] lineData = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
							IPAddress dns;
							if ((lineData.Length == 2) && (lineData[0] == "nameserver") && (IPAddress.TryParse(lineData[1], out dns)))
							{
								res.Add(dns);
							}
						}
					}
				}
				catch (Exception e)
				{
					Trace.TraceError("/etc/resolv.conf could not be parsed: " + e);
				}
			}

			if (res.Count == 0)
			{
				// fallback: use the public dns-resolvers of google
				res.Add(IPAddress.Parse("8.8.4.4"));
				res.Add(IPAddress.Parse("8.8.8.8"));
			}

			return res.OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 1 : 0).ToList();
		}
	}
}