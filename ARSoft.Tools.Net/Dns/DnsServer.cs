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
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	/// Provides a base dns server interface
	/// </summary>
	public class DnsServer : IDisposable
	{
		/// <summary>
		/// Represents the method, that will be called to get the response for a specific dns query
		/// </summary>
		/// <param name="query">The query, for that a response should be returned</param>
		/// <param name="clientAddress">The ip address from which the queries comes</param>
		/// <param name="protocolType">The protocol which was used for the query</param>
		/// <returns>A DnsMessage with the response to the query</returns>
		public delegate DnsMessageBase ProcessQuery(DnsMessageBase query, IPAddress clientAddress, ProtocolType protocolType);

		/// <summary>
		/// Represents the method, that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		/// <param name="algorithm">The algorithm which is used in the message</param>
		/// <param name="keyName">The keyname which is used in the message</param>
		/// <returns>Binary representation of the key</returns>
		public delegate byte[] SelectTsigKey(TSigAlgorithm algorithm, string keyName);

		private const int _DNS_PORT = 53;

		private TcpListener _tcpListener;
		private UdpClient _udpClient;
		private readonly IPAddress _bindAddress;

		private readonly int _udpListenerCount;
		private readonly int _tcpListenerCount;

		private readonly ProcessQuery _processQueryDelegate;

		/// <summary>
		/// Method that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		public SelectTsigKey TsigKeySelector;

		/// <summary>
		/// Gets or sets the timeout for sending and receiving data
		/// </summary>
		public int Timeout { get; set; }

		/// <summary>
		/// Creates a new dns server instance which will listen on all available interfaces
		/// </summary>
		/// <param name="udpListenerCount">The count of threads listings on udp, 0 to deactivate udp</param>
		/// <param name="tcpListenerCount">The count of threads listings on tcp, 0 to deactivate tcp</param>
		/// <param name="processQuery">Method, which process the queries and returns the response</param>
		public DnsServer(int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
			: this(IPAddress.Any, udpListenerCount, tcpListenerCount, processQuery) {}

		/// <summary>
		/// Creates a new dns server instance
		/// </summary>
		/// <param name="bindAddress">The address, on which should be listend</param>
		/// <param name="udpListenerCount">The count of threads listings on udp, 0 to deactivate udp</param>
		/// <param name="tcpListenerCount">The count of threads listings on tcp, 0 to deactivate tcp</param>
		/// <param name="processQuery">Method, which process the queries and returns the response</param>
		public DnsServer(IPAddress bindAddress, int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
		{
			_bindAddress = bindAddress;
			_processQueryDelegate = processQuery;

			_udpListenerCount = udpListenerCount;
			_tcpListenerCount = tcpListenerCount;
		}

		/// <summary>
		/// Starts the server
		/// </summary>
		public void Start()
		{
			if (_udpListenerCount > 0)
			{
				_udpClient = new UdpClient(new IPEndPoint(_bindAddress, _DNS_PORT));
				for (int i = 0; i < _udpListenerCount; i++)
				{
					StartUdpListen();
				}
			}

			if (_tcpListenerCount > 0)
			{
				_tcpListener = new TcpListener(_bindAddress, _DNS_PORT);
				_tcpListener.Start();
				for (int i = 0; i < _tcpListenerCount; i++)
				{
					StartTcpAcceptConnection();
				}
			}
		}

		/// <summary>
		/// Stops the server
		/// </summary>
		public void Stop()
		{
			if (_udpListenerCount > 0)
			{
				_udpClient.Close();
			}
			if (_tcpListenerCount > 0)
			{
				_tcpListener.Stop();
			}
		}

		private void StartUdpListen()
		{
			try
			{
				_udpClient.BeginReceive(EndUdpReceive, null);
			}
			catch (Exception e)
			{
				OnExceptionThrown(e);
			}
		}

		private void EndUdpReceive(IAsyncResult ar)
		{
			try
			{
				IPEndPoint endpoint = new IPEndPoint(IPAddress.Any, _DNS_PORT);

				byte[] buffer = _udpClient.EndReceive(ar, ref endpoint);

				DnsMessageBase query;
				try
				{
					query = DnsMessageBase.Create(buffer, true, TsigKeySelector, null);
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessageBase response = ProcessMessage(query, endpoint.Address, ProtocolType.Udp);

				if (response == null)
				{
					response = query;
					query.IsQuery = false;
					query.ReturnCode = ReturnCode.ServerFailure;
				}

				int length = response.Encode(out buffer, false);

				#region Truncating
				DnsMessage message = response as DnsMessage;

				if (message != null)
				{
					int maxLength = 512;
					if (query.IsEDnsEnabled && message.IsEDnsEnabled)
					{
						maxLength = Math.Max(512, (int) message.EDnsOptions.UpdPayloadSize);
					}

					while (length > maxLength)
					{
						// First step: remove data from additional records except the opt record
						if ((message.IsEDnsEnabled && (message.AdditionalRecords.Count > 1)) || (!message.IsEDnsEnabled && (message.AdditionalRecords.Count > 0)))
						{
							for (int i = message.AdditionalRecords.Count - 1; i >= 0; i--)
							{
								if (message.AdditionalRecords[i].RecordType != RecordType.Opt)
								{
									message.AdditionalRecords.RemoveAt(i);
								}
							}

							length = message.Encode(out buffer, false);
							continue;
						}

						int savedLength = 0;
						if (message.AuthorityRecords.Count > 0)
						{
							for (int i = message.AuthorityRecords.Count - 1; i >= 0; i--)
							{
								savedLength += message.AuthorityRecords[i].MaximumLength;
								message.AuthorityRecords.RemoveAt(i);

								if ((length - savedLength) < maxLength)
								{
									break;
								}
							}

							message.IsTruncated = true;

							length = message.Encode(out buffer, false);
							continue;
						}

						if (message.AnswerRecords.Count > 0)
						{
							for (int i = message.AnswerRecords.Count - 1; i >= 0; i--)
							{
								savedLength += message.AnswerRecords[i].MaximumLength;
								message.AnswerRecords.RemoveAt(i);

								if ((length - savedLength) < maxLength)
								{
									break;
								}
							}

							message.IsTruncated = true;

							length = message.Encode(out buffer, false);
							continue;
						}

						if (message.Questions.Count > 0)
						{
							for (int i = message.Questions.Count - 1; i >= 0; i--)
							{
								savedLength += message.Questions[i].MaximumLength;
								message.Questions.RemoveAt(i);

								if ((length - savedLength) < maxLength)
								{
									break;
								}
							}

							message.IsTruncated = true;

							length = message.Encode(out buffer, false);
							continue;
						}
					}
				}
				#endregion

				_udpClient.BeginSend(buffer, length, endpoint, EndUdpSend, null);
			}
			catch (Exception e)
			{
				OnExceptionThrown(e);
			}

			StartUdpListen();
		}

		private DnsMessageBase ProcessMessage(DnsMessageBase query, IPAddress ipAddress, ProtocolType protocolType)
		{
			if (query.TSigOptions != null)
			{
				switch (query.TSigOptions.ValidationResult)
				{
					case ReturnCode.BadKey:
					case ReturnCode.BadSig:
						query.IsQuery = false;
						query.ReturnCode = ReturnCode.NotAuthoritive;
						query.TSigOptions.Error = query.TSigOptions.ValidationResult;
						query.TSigOptions.KeyData = null;

						if (InvalidSignedMessageReceived != null)
							InvalidSignedMessageReceived(this, new InvalidSignedMessageEventArgs(query));

						return query;

					case ReturnCode.BadTime:
						query.IsQuery = false;
						query.ReturnCode = ReturnCode.NotAuthoritive;
						query.TSigOptions.Error = query.TSigOptions.ValidationResult;
						query.TSigOptions.OtherData = new byte[6];
						int tmp = 0;
						TSigRecord.EncodeDateTime(query.TSigOptions.OtherData, ref tmp, DateTime.Now);

						if (InvalidSignedMessageReceived != null)
							InvalidSignedMessageReceived(this, new InvalidSignedMessageEventArgs(query));

						return query;
				}
			}

			return _processQueryDelegate(query, ipAddress, protocolType);
		}

		private void EndUdpSend(IAsyncResult ar)
		{
			_udpClient.EndSend(ar);
		}

		private void StartTcpAcceptConnection()
		{
			try
			{
				_tcpListener.BeginAcceptTcpClient(EndTcpAcceptConnection, null);
			}
			catch (Exception e)
			{
				OnExceptionThrown(e);
			}
		}

		private void EndTcpAcceptConnection(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				client = _tcpListener.EndAcceptTcpClient(ar);
				stream = client.GetStream();
				byte[] buffer = new byte[2];

				Timer timer = new Timer(TcpTimedOut, new object[] { client, stream }, 120000, System.Threading.Timeout.Infinite);
				stream.BeginRead(buffer, 0, 2, EndTcpReadLength, new object[] { client, stream, buffer, timer });
			}
			catch (Exception e)
			{
				try
				{
					if (stream != null)
					{
						stream.Close();
					}
				}
				catch {}

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch {}

				OnExceptionThrown(e);
			}

			StartTcpAcceptConnection();
		}

		private static void TcpTimedOut(object ar)
		{
			IAsyncResult asyncResult = (IAsyncResult) ar;

			if (!asyncResult.IsCompleted)
			{
				object[] state = (object[]) asyncResult.AsyncState;
				TcpClient client = (TcpClient) state[0];
				NetworkStream stream = (NetworkStream) state[1];

				try
				{
					if (stream != null)
					{
						stream.Close();
					}
				}
				catch {}

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch {}
			}
		}

		private void EndTcpReadLength(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				object[] state = (object[]) ar.AsyncState;
				client = (TcpClient) state[0];
				stream = (NetworkStream) state[1];
				byte[] buffer = (byte[]) state[2];

				Timer timer = (Timer) state[3];
				timer.Dispose();

				stream.EndRead(ar);

				int tmp = 0;
				int length = DnsMessageBase.ParseUShort(buffer, ref tmp);

				if (length > 0)
				{
					buffer = new byte[length];

					timer = new Timer(TcpTimedOut, new object[] { client, stream }, 120000, System.Threading.Timeout.Infinite);
					stream.BeginRead(buffer, 0, length, EndTcpReadData, new object[] { client, stream, buffer, timer });
				}
			}
			catch (Exception e)
			{
				try
				{
					if (stream != null)
					{
						stream.Close();
					}
				}
				catch {}

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch {}

				OnExceptionThrown(e);
			}
		}

		private void EndTcpReadData(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				object[] state = (object[]) ar.AsyncState;
				client = (TcpClient) state[0];
				stream = (NetworkStream) state[1];
				byte[] buffer = (byte[]) state[2];

				Timer timer = (Timer) state[3];
				timer.Dispose();

				stream.EndRead(ar);

				DnsMessageBase query;

				try
				{
					query = DnsMessageBase.Create(buffer, true, TsigKeySelector, null);
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessageBase response = ProcessMessage(query, ((IPEndPoint) client.Client.RemoteEndPoint).Address, ProtocolType.Tcp);

				if (response == null)
				{
					response = query;
					query.IsQuery = false;
					query.ReturnCode = ReturnCode.ServerFailure;
				}

				int length = response.Encode(out buffer, true);

				timer = new Timer(TcpTimedOut, new object[] { client, stream }, 120000, System.Threading.Timeout.Infinite);
				stream.BeginWrite(buffer, 0, length, EndTcpSendData, new object[] { client, stream, timer });
			}
			catch (Exception e)
			{
				try
				{
					if (stream != null)
					{
						stream.Close();
					}
				}
				catch {}

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch {}

				OnExceptionThrown(e);
			}
		}

		private void EndTcpSendData(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				object[] state = (object[]) ar.AsyncState;
				client = (TcpClient) state[0];
				stream = (NetworkStream) state[1];

				Timer timer = (Timer) state[2];
				timer.Dispose();

				stream.EndWrite(ar);

				byte[] buffer = new byte[2];

				timer = new Timer(TcpTimedOut, new object[] { client, stream }, 120000, System.Threading.Timeout.Infinite);
				stream.BeginRead(buffer, 0, 2, EndTcpReadLength, new object[] { client, stream, buffer, timer });
			}
			catch (Exception e)
			{
				try
				{
					if (stream != null)
					{
						stream.Close();
					}
				}
				catch {}

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch {}

				OnExceptionThrown(e);
			}
		}

		private void OnExceptionThrown(Exception e)
		{
			if (ExceptionThrown != null)
			{
				ExceptionThrown(this, new ExceptionEventArgs(e));
			}
			else
			{
				Trace.TraceError(e.ToString());
			}
		}

		/// <summary>
		/// This event is fired on exceptions of the listeners. You can use it for custom logging.
		/// </summary>
		public event EventHandler<ExceptionEventArgs> ExceptionThrown;

		/// <summary>
		/// This event is fired whenever a message is received, that is not correct signed
		/// </summary>
		public event EventHandler<InvalidSignedMessageEventArgs> InvalidSignedMessageReceived;

		void IDisposable.Dispose()
		{
			Stop();
		}
	}
}