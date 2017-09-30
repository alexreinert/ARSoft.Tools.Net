using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.Diagnostics;

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
		/// <returns>A DnsMessage with the response to the query</returns>
		public delegate DnsMessage ProcessQuery(DnsMessage query, IPAddress clientAddress, ProtocolType protocolType);

		private const int _DNS_PORT = 53;

		private IPAddress _bindAddress;
		private TcpListener _tcpListener;
		private UdpClient _udpClient;

		private int _udpListenerCount;
		private int _tcpListenerCount;

		private bool _isShutdownRequested;

		private ProcessQuery _processQueryDelegate;

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
			: this(IPAddress.Any, udpListenerCount, tcpListenerCount, processQuery)
		{
		}

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
			_isShutdownRequested = false;

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
			_isShutdownRequested = true;

			if (_udpListenerCount > 0)
			{
				_udpClient.Close();
			}
			if (_tcpListenerCount > 0)
			{
				_udpClient.Close();
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

				DnsMessage query = new DnsMessage();
				try
				{
					query.Parse(buffer);
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessage response = _processQueryDelegate(query, endpoint.Address, ProtocolType.Udp);

				if (response == null)
				{
					response = query;
					query.IsQuery = false;
					query.ReturnCode = ReturnCode.ServerFailure;
				}

				int length = response.Encode(out buffer);

				#region Truncating
				int maxLength = 512;
				if (query.IsEDnsEnabled && response.IsEDnsEnabled)
				{
					maxLength = Math.Max(512, (int)response.EDnsOptions.UpdPayloadSize);
				}

				while (length > maxLength)
				{
					// First step: remove data from additional records except the opt record
					if ((response.IsEDnsEnabled && (response.AdditionalRecords.Count > 1)) || (!response.IsEDnsEnabled && (response.AdditionalRecords.Count > 0)))
					{
						for (int i = response.AdditionalRecords.Count - 1; i >= 0; i--)
						{
							if (response.AdditionalRecords[i].RecordType != RecordType.Opt)
							{
								response.AdditionalRecords.RemoveAt(i);
							}
						}

						length = response.Encode(out buffer);
						continue;
					}

					int savedLength = 0;
					if (response.AuthorityRecords.Count > 0)
					{
						for (int i = response.AuthorityRecords.Count - 1; i >= 0; i--)
						{
							savedLength += response.AuthorityRecords[i].MaximumLength;
							response.AuthorityRecords.RemoveAt(i);

							if ((length - savedLength) < maxLength)
							{
								break;
							}
						}

						response.IsTruncated = true;

						length = response.Encode(out buffer);
						continue;
					}

					if (response.AnswerRecords.Count > 0)
					{
						for (int i = response.AnswerRecords.Count - 1; i >= 0; i--)
						{
							savedLength += response.AnswerRecords[i].MaximumLength;
							response.AnswerRecords.RemoveAt(i);

							if ((length - savedLength) < maxLength)
							{
								break;
							}
						}

						response.IsTruncated = true;

						length = response.Encode(out buffer);
						continue;
					}

					if (response.Questions.Count > 0)
					{
						for (int i = response.Questions.Count - 1; i >= 0; i--)
						{
							savedLength += response.Questions[i].MaximumLength;
							response.Questions.RemoveAt(i);

							if ((length - savedLength) < maxLength)
							{
								break;
							}
						}

						response.IsTruncated = true;

						length = response.Encode(out buffer);
						continue;
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
				catch { }

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch { }

				OnExceptionThrown(e);
			}

			StartTcpAcceptConnection();
		}

		private void TcpTimedOut(object ar)
		{
			IAsyncResult asyncResult = (IAsyncResult)ar;

			if (!asyncResult.IsCompleted)
			{
				object[] state = (object[])asyncResult.AsyncState;
				TcpClient client = (TcpClient)state[0];
				NetworkStream stream = (NetworkStream)state[1];

				try
				{
					if (stream != null)
					{
						stream.Close();
					}
				}
				catch { }

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch { }
			}
		}

		private void EndTcpReadLength(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				object[] state = (object[])ar.AsyncState;
				client = (TcpClient)state[0];
				stream = (NetworkStream)state[1];
				byte[] buffer = (byte[])state[2];

				Timer timer = (Timer)state[3];
				timer.Dispose();

				stream.EndRead(ar);

				int tmp = 0;
				int length = (int)DnsMessage.ParseUShort(buffer, ref tmp);

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
				catch { }

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch { }

				OnExceptionThrown(e);
			}
		}

		private void EndTcpReadData(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				object[] state = (object[])ar.AsyncState;
				client = (TcpClient)state[0];
				stream = (NetworkStream)state[1];
				byte[] buffer = (byte[])state[2];

				Timer timer = (Timer)state[3];
				timer.Dispose();

				stream.EndRead(ar);

				DnsMessage query = new DnsMessage();

				try
				{
					query.Parse(buffer);
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessage response = _processQueryDelegate(query, ((IPEndPoint)client.Client.RemoteEndPoint).Address, ProtocolType.Tcp);

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
				catch { }

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch { }

				OnExceptionThrown(e);
			}
		}

		private void EndTcpSendData(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				object[] state = (object[])ar.AsyncState;
				client = (TcpClient)state[0];
				stream = (NetworkStream)state[1];

				Timer timer = (Timer)state[2];
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
				catch { }

				try
				{
					if (client != null)
					{
						client.Close();
					}
				}
				catch { }

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
		/// This event in fired on exceptions of the listeners. You can use it for custom logging.
		/// </summary>
		public event EventHandler<ExceptionEventArgs> ExceptionThrown;

		void IDisposable.Dispose()
		{
			Stop();
		}
	}
}
