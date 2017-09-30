using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.IO;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	/// Provides a client for querying dns records
	/// </summary>
	public class DnsClient
	{
		private const int _DNS_PORT = 53;
		private List<IPAddress> _dnsServers;
		public int QueryTimeout { get; set; }

		/// <summary>
		/// Returns a default instance of the DnsClient, which uses the configured dns servers of the executing computer and a query timeout of 10 seconds.
		/// </summary>
		public static DnsClient Default { get; private set; }

		static DnsClient()
		{
			Default = new DnsClient(GetDnsServers(), 10000);
		}

		/// <summary>
		/// Provides a new instance with custom dns server and query timeout
		/// </summary>
		/// <param name="dnsServers">The IPAddress of the dns server to use</param>
		/// <param name="queryTimeout">Query timeout in milliseconds</param>
		public DnsClient(IPAddress dnsServers, int queryTimeout)
		{
			_dnsServers = new List<IPAddress>() { dnsServers };
			QueryTimeout = queryTimeout;
		}

		/// <summary>
		/// Provides a new instance with custom dns servers and query timeout
		/// </summary>
		/// <param name="dnsServers">The IPAddresses of the dns servers to use</param>
		/// <param name="queryTimeout">Query timeout in milliseconds</param>
		public DnsClient(List<IPAddress> dnsServers, int queryTimeout)
		{
			_dnsServers = dnsServers;
			QueryTimeout = queryTimeout;
		}

		/// <summary>
		/// Queries a dns server for address records.
		/// </summary>
		/// <param name="name">Domain, that should be queried</param>
		/// <returns>The complete response of the dns server</returns>
		public DnsMessage Resolve(string name)
		{
			return Resolve(name, RecordType.A, RecordClass.INet);
		}

		/// <summary>
		/// Queries a dns server for specified records.
		/// </summary>
		/// <param name="name">Domain, that should be queried</param>
		/// <param name="recordType">Recordtype the should be queried</param>
		/// <returns>The complete response of the dns server</returns>
		public DnsMessage Resolve(string name, RecordType recordType)
		{
			return Resolve(name, recordType, RecordClass.INet);
		}

		/// <summary>
		/// Queries a dns server for specified records.
		/// </summary>
		/// <param name="name">Domain, that should be queried</param>
		/// <param name="recordType">Type the should be queried</param>
		/// <param name="recordClass">Class the should be queried</param>
		/// <returns>The complete response of the dns server</returns>
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
		/// Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name">Domain, that should be queried</param>
		/// <param name="requestCallback">An <see cref="System.AsyncCallback"/> delegate that references the method to invoked then the operation is complete.</param>
		/// <param name="state">A user-defined object that contains information about the receive operation. This object is passed to the <paramref name="requestCallback"/> delegate when the operation is complete.</param>
		/// <returns>An <see cref="System.IAsyncResult"/> IAsyncResult object that references the asynchronous receive.</returns>
		public IAsyncResult BeginResolve(string name, AsyncCallback requestCallback, object state)
		{
			return BeginResolve(name, RecordType.A, RecordClass.INet, requestCallback, state);
		}

		/// <summary>
		/// Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name">Domain, that should be queried</param>
		/// <param name="recordType">Type the should be queried</param>
		/// <param name="requestCallback">An <see cref="System.AsyncCallback"/> delegate that references the method to invoked then the operation is complete.</param>
		/// <param name="state">A user-defined object that contains information about the receive operation. This object is passed to the <paramref name="requestCallback"/> delegate when the operation is complete.</param>
		/// <returns>An <see cref="System.IAsyncResult"/> IAsyncResult object that references the asynchronous receive.</returns>
		public IAsyncResult BeginResolve(string name, RecordType recordType, AsyncCallback requestCallback, object state)
		{
			return BeginResolve(name, recordType, RecordClass.INet, requestCallback, state);
		}

		/// <summary>
		/// Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name">Domain, that should be queried</param>
		/// <param name="recordType">Type the should be queried</param>
		/// <param name="recordClass">Class the should be queried</param>
		/// <param name="requestCallback">An <see cref="System.AsyncCallback"/> delegate that references the method to invoked then the operation is complete.</param>
		/// <param name="state">A user-defined object that contains information about the receive operation. This object is passed to the <paramref name="requestCallback"/> delegate when the operation is complete.</param>
		/// <returns>An <see cref="System.IAsyncResult"/> IAsyncResult object that references the asynchronous receive.</returns>
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
		/// Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar">An <see cref="System.IAsyncResult"/> object returned by a call to <see cref="ARSoft.Tools.Net.Dns.DnsClient.BeginResolve"/>.</param>
		/// <returns>The complete response of the dns server</returns>
		public DnsMessage EndResolve(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar;
			return state.Response;
		}

		/// <summary>
		/// Send a custom message to the dns server and returns the answer.
		/// </summary>
		/// <param name="message">Message, that should be send to the dns server</param>
		/// <returns>The complete response of the dns server</returns>
		public DnsMessage SendMessage(DnsMessage message)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if ((message.Questions == null) || (message.Questions.Count == 0))
				throw new ArgumentException("At least one question must be provided", "message");

			byte[] messageData;
			int messageLength = message.Encode(out messageData);

			foreach (IPAddress nameServer in _dnsServers)
			{
				bool sendByTcp = ((messageLength > 512) || (message.Questions[0].RecordType == RecordType.Axfr) || (message.Questions[0].RecordType == RecordType.Ixfr));
				byte[] resultData = resultData = sendByTcp ? QueryByTcp(nameServer, messageData, messageLength) : QueryByUdp(nameServer, messageData, messageLength);

				if (resultData != null)
				{
					DnsMessage result = new DnsMessage();
					result.Parse(resultData);

					if (result.IsTruncated)
					{
						resultData = QueryByTcp(nameServer, messageData, messageLength);
						if (resultData != null)
						{
							result = new DnsMessage();
							result.Parse(resultData);
							return result;
						}
					}
					else
					{
						return result;
					}
				}
			}

			return null;
		}

		private byte[] QueryByUdp(IPAddress nameServer, byte[] messageData, int messageLength)
		{
			IPEndPoint endPoint = new IPEndPoint(nameServer, _DNS_PORT);
			byte[] resultData;

			using (UdpClient udpClient = new UdpClient(nameServer.AddressFamily))
			{
				try
				{
					udpClient.Client.ReceiveTimeout = QueryTimeout;
					udpClient.Connect(endPoint);
					udpClient.Send(messageData, messageLength);
					resultData = udpClient.Receive(ref endPoint);

					return resultData;
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

			byte[] resultData;

			using (TcpClient tcpClient = new TcpClient(nameServer.AddressFamily))
			{
				try
				{
					tcpClient.ReceiveTimeout = QueryTimeout;
					tcpClient.SendTimeout = QueryTimeout;
					tcpClient.Connect(endPoint);

					using (NetworkStream tcpStream = tcpClient.GetStream())
					{
						int tmp = 0;

						byte[] lengthBuffer = new byte[2];
						DnsMessage.EncodeUShort(lengthBuffer, ref tmp, (ushort)messageLength);

						tcpStream.Write(lengthBuffer, 0, 2);
						tcpStream.Write(messageData, 0, messageLength);

						lengthBuffer[0] = (byte)tcpStream.ReadByte();
						lengthBuffer[1] = (byte)tcpStream.ReadByte();

						tmp = 0;
						int length = DnsMessage.ParseUShort(lengthBuffer, ref tmp);

						resultData = new byte[length];
						tcpStream.Read(resultData, 0, length);
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
		/// Send a custom message to the dns server and returns the answer asynchronously.
		/// </summary>
		/// <param name="message">Message, that should be send to the dns server</param>
		/// <param name="requestCallback">An <see cref="System.AsyncCallback"/> delegate that references the method to invoked then the operation is complete.</param>
		/// <param name="state">A user-defined object that contains information about the receive operation. This object is passed to the <paramref name="requestCallback"/> delegate when the operation is complete.</param>
		/// <returns>An <see cref="System.IAsyncResult"/> IAsyncResult object that references the asynchronous receive.</returns>
		public IAsyncResult BeginSendMessage(DnsMessage message, AsyncCallback requestCallback, object state)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if ((message.Questions == null) || (message.Questions.Count == 0))
				throw new ArgumentException("At least one question must be provided", "message");

			if (message.TransactionID == 0)
			{
				message.TransactionID = (ushort)new Random().Next(0xffff);
			}

			byte[] queryData;
			int queryLength = message.Encode(out queryData);

			DnsAsyncState asyncResult = new DnsAsyncState() { QueryData = queryData, QueryLength = queryLength, UserCallback = requestCallback, AsyncState = state, ServerEnumerator = _dnsServers.GetEnumerator() };

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
		/// Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar">An <see cref="System.IAsyncResult"/> object returned by a call to <see cref="ARSoft.Tools.Net.Dns.DnsClient.BeginSendMessage"/>.</param>
		/// <returns>The complete response of the dns server</returns>
		public DnsMessage EndSendMessage(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar;
			return state.Response;
		}

		#region Event handling async udp query
		private void UdpBeginSend(DnsAsyncState state)
		{
			if (!state.ServerEnumerator.MoveNext())
			{
				state.Response = null;
				state.UdpClient = null;
				state.UdpEndpoint = null;
				state.SetCompleted();
				return;
			}

			state.UdpEndpoint = new IPEndPoint(state.ServerEnumerator.Current, _DNS_PORT);

			state.UdpClient = new UdpClient(state.UdpEndpoint.AddressFamily);
			state.UdpClient.Connect(state.UdpEndpoint);
			state.TimedOut = false;

			IAsyncResult asyncResult = state.UdpClient.BeginSend(state.QueryData, state.QueryLength, UdpSendCompleted, state);
			state.Timer = new Timer(UdpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
		}

		private void UdpTimedOut(object ar)
		{
			IAsyncResult asyncResult = (IAsyncResult)ar;

			if (!asyncResult.IsCompleted)
			{
				DnsAsyncState state = (DnsAsyncState)asyncResult.AsyncState;
				state.TimedOut = true;
				state.UdpClient.Close();
			}
		}

		private void UdpSendCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				UdpBeginSend(state);
			}
			else
			{
				state.UdpClient.EndSend(ar);

				IAsyncResult asyncResult = state.UdpClient.BeginReceive(UdpReceiveCompleted, state);
				state.Timer = new Timer(UdpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
			}
		}

		private void UdpReceiveCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				UdpBeginSend(state);
			}
			else
			{
				byte[] responseData = state.UdpClient.EndReceive(ar, ref state.UdpEndpoint);

				state.UdpClient.Close();
				state.UdpClient = null;
				state.UdpEndpoint = null;

				state.Response = new DnsMessage();
				state.Response.Parse(responseData);

				if (state.Response.IsTruncated)
				{
					TcpBeginConnect(state);
					return;
				}

				state.SetCompleted();
			}
		}
		#endregion

		#region Event handling async tcp query
		private void TcpBeginConnect(DnsAsyncState state)
		{
			if (!state.ServerEnumerator.MoveNext())
			{
				state.Response = null;
				state.TcpStream = null;
				state.TcpClient = null;
				state.SetCompleted();
				return;
			}

			state.UdpEndpoint = new IPEndPoint(state.ServerEnumerator.Current, _DNS_PORT);

			state.TcpClient = new TcpClient(state.ServerEnumerator.Current.AddressFamily);
			state.TimedOut = false;

			IAsyncResult asyncResult = state.TcpClient.BeginConnect(state.ServerEnumerator.Current, _DNS_PORT, TcpConnectCompleted, state);
			state.Timer = new Timer(TcpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
		}

		private void TcpTimedOut(object ar)
		{
			IAsyncResult asyncResult = (IAsyncResult)ar;

			if (!asyncResult.IsCompleted)
			{
				DnsAsyncState state = (DnsAsyncState)asyncResult.AsyncState;
				state.TimedOut = true;
				if (state.TcpStream != null)
					state.TcpStream.Close();
				state.TcpClient.Close();
			}
		}

		private void TcpConnectCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpClient.EndConnect(ar);

				state.TcpStream = state.TcpClient.GetStream();

				int tmp = 0;

				state.TcpBuffer = new byte[2];
				DnsMessage.EncodeUShort(state.TcpBuffer, ref tmp, (ushort)state.QueryLength);

				IAsyncResult asyncResult = state.TcpStream.BeginWrite(state.TcpBuffer, 0, 2, TcpSendLengthCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
			}
		}

		private void TcpSendLengthCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpStream.EndWrite(ar);

				IAsyncResult asyncResult = state.TcpStream.BeginWrite(state.QueryData, 0, state.QueryLength, TcpSendCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
			}
		}

		private void TcpSendCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpStream.EndWrite(ar);

				IAsyncResult asyncResult = state.TcpStream.BeginRead(state.TcpBuffer, 0, 2, TcpReceiveLengthCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
			}
		}

		private void TcpReceiveLengthCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpStream.EndRead(ar);

				int tmp = 0;
				int responseLength = DnsMessage.ParseUShort(state.TcpBuffer, ref tmp);

				state.TcpBuffer = new byte[responseLength];

				IAsyncResult asyncResult = state.TcpStream.BeginRead(state.TcpBuffer, 0, responseLength, TcpReceiveCompleted, state);
				state.Timer = new Timer(TcpTimedOut, asyncResult, QueryTimeout, Timeout.Infinite);
			}
		}

		private void TcpReceiveCompleted(IAsyncResult ar)
		{
			DnsAsyncState state = (DnsAsyncState)ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				TcpBeginConnect(state);
			}
			else
			{
				state.TcpStream.EndRead(ar);

				state.Response = new DnsMessage();
				state.Response.Parse(state.TcpBuffer);

				state.TcpStream.Close();
				state.TcpClient.Close();
				state.TcpStream = null;
				state.TcpClient = null;

				state.TcpBuffer = null;
				state.SetCompleted();
			}
		}
		#endregion

		private static List<IPAddress> GetDnsServers()
		{
			List<IPAddress> res = new List<IPAddress>();

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

			// try parsing resolv.conf since getting data by NetworkInterface is not supported on non-windows mono
			if ((res.Count == 0) && ((Environment.OSVersion.Platform == PlatformID.Unix) || (Environment.OSVersion.Platform == PlatformID.MacOSX)))
			{
				try
				{
					using (StreamReader reader = File.OpenText("/etc/resolv.conf"))
					{
						while (!reader.EndOfStream)
						{
							string line = reader.ReadLine();

							int commentStart = line.IndexOf('#');
							if (commentStart != -1)
							{
								line = line.Substring(0, commentStart);
							}

							string[] lineData = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
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

			return res;
		}
	}
}
