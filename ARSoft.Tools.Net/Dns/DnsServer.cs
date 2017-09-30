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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using ARSoft.Tools.Net.Socket;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides a base dns server interface
	/// </summary>
	public class DnsServer : IDisposable
	{
		private class MyState
		{
			public IAsyncResult AsyncResult;
			public TcpClient Client;
			public NetworkStream Stream;
			public byte[] Buffer;
			public int BytesToReceive;
			public Timer Timer;

			private long _timeOutUtcTicks;

			public long TimeRemaining
			{
				get
				{
					long res = (_timeOutUtcTicks - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerMillisecond;
					return res > 0 ? res : 0;
				}
				set { _timeOutUtcTicks = DateTime.UtcNow.Ticks + value * TimeSpan.TicksPerMillisecond; }
			}
		}

		/// <summary>
		///   Represents the method, that will be called to get the response for a specific dns query
		/// </summary>
		/// <param name="query"> The query, for that a response should be returned </param>
		/// <param name="clientAddress"> The ip address from which the queries comes </param>
		/// <param name="protocolType"> The protocol which was used for the query </param>
		/// <returns> A DnsMessage with the response to the query </returns>
		public delegate DnsMessageBase ProcessQuery(DnsMessageBase query, IPAddress clientAddress, ProtocolType protocolType);

		/// <summary>
		///   Represents the method, that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		/// <param name="algorithm"> The algorithm which is used in the message </param>
		/// <param name="keyName"> The keyname which is used in the message </param>
		/// <returns> Binary representation of the key </returns>
		public delegate byte[] SelectTsigKey(TSigAlgorithm algorithm, string keyName);

		private const int _DNS_PORT = 53;

		private TcpListener _tcpListener;
		private UdpListener _udpListener;
		private readonly IPEndPoint _bindEndPoint;

		private readonly int _udpListenerCount;
		private readonly int _tcpListenerCount;

		private readonly ProcessQuery _processQueryDelegate;

		/// <summary>
		///   Method that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		public SelectTsigKey TsigKeySelector;

		/// <summary>
		///   Gets or sets the timeout for sending and receiving data
		/// </summary>
		public int Timeout { get; set; }

		/// <summary>
		///   Creates a new dns server instance which will listen on all available interfaces
		/// </summary>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		/// <param name="processQuery"> Method, which process the queries and returns the response </param>
		public DnsServer(int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
			: this(IPAddress.Any, udpListenerCount, tcpListenerCount, processQuery) {}

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="bindAddress"> The address, on which should be listend </param>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		/// <param name="processQuery"> Method, which process the queries and returns the response </param>
		public DnsServer(IPAddress bindAddress, int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
			: this(new IPEndPoint(bindAddress, _DNS_PORT), udpListenerCount, tcpListenerCount, processQuery) {}

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="bindEndPoint"> The endpoint, on which should be listend </param>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		/// <param name="processQuery"> Method, which process the queries and returns the response </param>
		public DnsServer(IPEndPoint bindEndPoint, int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
		{
			_bindEndPoint = bindEndPoint;
			_processQueryDelegate = processQuery;

			_udpListenerCount = udpListenerCount;
			_tcpListenerCount = tcpListenerCount;

			Timeout = 120000;
		}

		/// <summary>
		///   Starts the server
		/// </summary>
		public void Start()
		{
			if (_udpListenerCount > 0)
			{
				_udpListener = new UdpListener(_bindEndPoint);
				for (int i = 0; i < _udpListenerCount; i++)
				{
					StartUdpListen();
				}
			}

			if (_tcpListenerCount > 0)
			{
				_tcpListener = new TcpListener(_bindEndPoint);
				_tcpListener.Start();
				for (int i = 0; i < _tcpListenerCount; i++)
				{
					StartTcpAcceptConnection();
				}
			}
		}

		/// <summary>
		///   Stops the server
		/// </summary>
		public void Stop()
		{
			if (_udpListenerCount > 0)
			{
				_udpListener.Dispose();
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
				_udpListener.BeginReceive(EndUdpReceive, null);
			}
			catch (ObjectDisposedException)
			{
				return;
			}
			catch (Exception e)
			{
				OnExceptionThrown(e);
				StartUdpListen();
			}
		}

		private void EndUdpReceive(IAsyncResult ar)
		{
			try
			{
				IPEndPoint endpoint;

				byte[] buffer = _udpListener.EndReceive(ar, out endpoint);

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

				int length = response.Encode(false, out buffer);

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

							length = message.Encode(false, out buffer);
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

							length = message.Encode(false, out buffer);
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

							length = message.Encode(false, out buffer);
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

							length = message.Encode(false, out buffer);
							continue;
						}
					}
				}
				#endregion

				_udpListener.BeginSend(buffer, 0, length, endpoint, EndUdpSend, null);
			}
			catch (ObjectDisposedException)
			{
				return;
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
			try
			{
				_udpListener.EndSend(ar);
			}
			catch (ObjectDisposedException) {}
		}

		private void StartTcpAcceptConnection()
		{
			try
			{
				_tcpListener.BeginAcceptTcpClient(EndTcpAcceptConnection, null);
			}
			catch (ObjectDisposedException) {}
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

				MyState state =
					new MyState()
					{
						Client = client,
						Stream = stream,
						Buffer = new byte[2],
						BytesToReceive = 2,
						TimeRemaining = Timeout
					};

				state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
				state.AsyncResult = stream.BeginRead(state.Buffer, 0, 2, EndTcpReadLength, state);
			}
			catch (ObjectDisposedException)
			{
				return;
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

		private static void TcpTimedOut(object timeoutState)
		{
			MyState state = timeoutState as MyState;

			if ((state != null) && (state.AsyncResult != null) && !state.AsyncResult.IsCompleted)
			{
				try
				{
					if (state.Stream != null)
					{
						state.Stream.Close();
					}
				}
				catch {}

				try
				{
					if (state.Client != null)
					{
						state.Client.Close();
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
				MyState state = (MyState) ar.AsyncState;
				client = state.Client;
				stream = state.Stream;

				state.Timer.Dispose();

				state.BytesToReceive -= stream.EndRead(ar);

				if (state.BytesToReceive > 0)
				{
					state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
					state.AsyncResult = stream.BeginRead(state.Buffer, state.Buffer.Length - state.BytesToReceive, state.BytesToReceive, EndTcpReadLength, state);
				}
				else
				{
					int tmp = 0;
					int length = DnsMessageBase.ParseUShort(state.Buffer, ref tmp);

					if (length > 0)
					{
						state.Buffer = new byte[length];

						state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
						state.AsyncResult = stream.BeginRead(state.Buffer, 0, length, EndTcpReadData, state);
					}
				}
			}
			catch (ObjectDisposedException)
			{
				return;
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
				MyState state = (MyState) ar.AsyncState;
				client = state.Client;
				stream = state.Stream;

				state.Timer.Dispose();

				state.BytesToReceive -= stream.EndRead(ar);

				if (state.BytesToReceive > 0)
				{
					state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
					state.AsyncResult = stream.BeginRead(state.Buffer, state.Buffer.Length - state.BytesToReceive, state.BytesToReceive, EndTcpReadData, state);
				}
				else
				{
					DnsMessageBase query;

					try
					{
						query = DnsMessageBase.Create(state.Buffer, true, TsigKeySelector, null);
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

					int length = response.Encode(true, out state.Buffer);

					state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
					state.AsyncResult = stream.BeginWrite(state.Buffer, 0, length, EndTcpSendData, state);
				}
			}
			catch (ObjectDisposedException)
			{
				return;
			}
			catch (Exception e)
			{
				if (e.InnerException is ObjectDisposedException)
					return;

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
				MyState state = (MyState) ar.AsyncState;
				client = state.Client;
				stream = state.Stream;

				state.Timer.Dispose();

				stream.EndWrite(ar);

				state.Buffer = new byte[2];

				state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
				state.AsyncResult = stream.BeginRead(state.Buffer, 0, 2, EndTcpReadLength, state);
			}
			catch (ObjectDisposedException)
			{
				return;
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
		///   This event is fired on exceptions of the listeners. You can use it for custom logging.
		/// </summary>
		public event EventHandler<ExceptionEventArgs> ExceptionThrown;

		/// <summary>
		///   This event is fired whenever a message is received, that is not correct signed
		/// </summary>
		public event EventHandler<InvalidSignedMessageEventArgs> InvalidSignedMessageReceived;

		void IDisposable.Dispose()
		{
			Stop();
		}
	}
}