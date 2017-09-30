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
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides a base dns server interface
	/// </summary>
	public class DnsServer : IDisposable
	{
		/// <summary>
		///   Represents the method, that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		/// <param name="algorithm"> The algorithm which is used in the message </param>
		/// <param name="keyName"> The keyname which is used in the message </param>
		/// <returns> Binary representation of the key </returns>
		public delegate byte[] SelectTsigKey(TSigAlgorithm algorithm, DomainName keyName);

		private const int _DNS_PORT = 53;

		private readonly object _listenerLock = new object();
		private TcpListener _tcpListener;
		private UdpClient _udpListener;
		private readonly IPEndPoint _bindEndPoint;

		private readonly int _udpListenerCount;
		private readonly int _tcpListenerCount;

		private int _availableUdpListener;
		private bool _hasActiveUdpListener;

		private int _availableTcpListener;
		private bool _hasActiveTcpListener;

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
		public DnsServer(int udpListenerCount, int tcpListenerCount)
			: this(IPAddress.Any, udpListenerCount, tcpListenerCount) {}

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="bindAddress"> The address, on which should be listend </param>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		public DnsServer(IPAddress bindAddress, int udpListenerCount, int tcpListenerCount)
			: this(new IPEndPoint(bindAddress, _DNS_PORT), udpListenerCount, tcpListenerCount) {}

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="bindEndPoint"> The endpoint, on which should be listend </param>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		public DnsServer(IPEndPoint bindEndPoint, int udpListenerCount, int tcpListenerCount)
		{
			_bindEndPoint = bindEndPoint;

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
				lock (_listenerLock)
				{
					_availableUdpListener = _udpListenerCount;
				}
				_udpListener = new UdpClient(_bindEndPoint);
				StartUdpListenerTask();
			}

			if (_tcpListenerCount > 0)
			{
				lock (_listenerLock)
				{
					_availableTcpListener = _tcpListenerCount;
				}
				_tcpListener = new TcpListener(_bindEndPoint);
				_tcpListener.Start();
				StartTcpListenerTask();
			}
		}

		/// <summary>
		///   Stops the server
		/// </summary>
		public void Stop()
		{
			if (_udpListenerCount > 0)
			{
				_udpListener.Close();
			}
			if (_tcpListenerCount > 0)
			{
				_tcpListener.Stop();
			}
		}

		private async Task<DnsMessageBase> ProcessMessageAsync(DnsMessageBase query, ProtocolType protocolType, IPEndPoint remoteEndpoint)
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

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, protocolType, remoteEndpoint));
#pragma warning restore 4014

						return query;

					case ReturnCode.BadTime:
						query.IsQuery = false;
						query.ReturnCode = ReturnCode.NotAuthoritive;
						query.TSigOptions.Error = query.TSigOptions.ValidationResult;
						query.TSigOptions.OtherData = new byte[6];
						int tmp = 0;
						TSigRecord.EncodeDateTime(query.TSigOptions.OtherData, ref tmp, DateTime.Now);

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, protocolType, remoteEndpoint));
#pragma warning restore 4014

						return query;
				}
			}

			QueryReceivedEventArgs eventArgs = new QueryReceivedEventArgs(query, protocolType, remoteEndpoint);
			await QueryReceived.RaiseAsync(this, eventArgs);
			return eventArgs.Response;
		}

		private void StartUdpListenerTask()
		{
			lock (_listenerLock)
			{
				if ((_udpListener.Client == null) || !_udpListener.Client.IsBound) // server is stopped
					return;

				if ((_availableUdpListener > 0) && !_hasActiveUdpListener)
				{
					_availableUdpListener--;
					_hasActiveUdpListener = true;
					HandleUdpListenerAsync();
				}
			}
		}

		private async void HandleUdpListenerAsync()
		{
			try
			{
				UdpReceiveResult receiveResult;
				try
				{
					receiveResult = await _udpListener.ReceiveAsync();
				}
				catch (ObjectDisposedException)
				{
					return;
				}
				finally
				{
					lock (_listenerLock)
					{
						_hasActiveUdpListener = false;
					}
				}

				ClientConnectedEventArgs clientConnectedEventArgs = new ClientConnectedEventArgs(ProtocolType.Udp, receiveResult.RemoteEndPoint);
				await ClientConnected.RaiseAsync(this, clientConnectedEventArgs);

				if (clientConnectedEventArgs.RefuseConnect)
					return;

				StartUdpListenerTask();

				byte[] buffer = receiveResult.Buffer;

				DnsMessageBase query;
				byte[] originalMac;
				try
				{
					query = DnsMessageBase.CreateByFlag(buffer, TsigKeySelector, null);
					originalMac = query.TSigOptions?.Mac;
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessageBase response;
				try
				{
					response = await ProcessMessageAsync(query, ProtocolType.Udp, receiveResult.RemoteEndPoint);
				}
				catch (Exception ex)
				{
					OnExceptionThrownAsync(ex);
					response = null;
				}

				if (response == null)
				{
					response = query;
					query.IsQuery = false;
					query.ReturnCode = ReturnCode.ServerFailure;
				}

				int length = response.Encode(false, originalMac, out buffer);

				#region Truncating
				DnsMessage message = response as DnsMessage;

				if (message != null)
				{
					int maxLength = 512;
					if (query.IsEDnsEnabled && message.IsEDnsEnabled)
					{
						maxLength = Math.Max(512, (int) message.EDnsOptions.UdpPayloadSize);
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

							length = message.Encode(false, originalMac, out buffer);
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

							length = message.Encode(false, originalMac, out buffer);
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

							length = message.Encode(false, originalMac, out buffer);
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

							length = message.Encode(false, originalMac, out buffer);
						}
					}
				}
				#endregion

				await _udpListener.SendAsync(buffer, length, receiveResult.RemoteEndPoint);
			}
			catch (Exception ex)
			{
				OnExceptionThrownAsync(ex);
			}
			finally
			{
				lock (_listenerLock)
				{
					_availableUdpListener++;
				}
				StartUdpListenerTask();
			}
		}

		private void StartTcpListenerTask()
		{
			lock (_listenerLock)
			{
				if ((_tcpListener.Server == null) || !_tcpListener.Server.IsBound) // server is stopped
					return;

				if ((_availableTcpListener > 0) && !_hasActiveTcpListener)
				{
					_availableTcpListener--;
					_hasActiveTcpListener = true;
					HandleTcpListenerAsync();
				}
			}
		}

		private async void HandleTcpListenerAsync()
		{
			TcpClient client = null;

			try
			{
				try
				{
					client = await _tcpListener.AcceptTcpClientAsync();

					ClientConnectedEventArgs clientConnectedEventArgs = new ClientConnectedEventArgs(ProtocolType.Tcp, (IPEndPoint) client.Client.RemoteEndPoint);
					await ClientConnected.RaiseAsync(this, clientConnectedEventArgs);

					if (clientConnectedEventArgs.RefuseConnect)
						return;
				}
				finally
				{
					lock (_listenerLock)
					{
						_hasActiveTcpListener = false;
					}
				}

				StartTcpListenerTask();

				using (NetworkStream stream = client.GetStream())
				{
					while (true)
					{
						byte[] buffer = await ReadIntoBufferAsync(client, stream, 2);
						if (buffer == null) // client disconneted while reading or timeout
							break;

						int offset = 0;
						int length = DnsMessageBase.ParseUShort(buffer, ref offset);

						buffer = await ReadIntoBufferAsync(client, stream, length);
						if (buffer == null) // client disconneted while reading or timeout
						{
							throw new Exception("Client disconnted or timed out while sending data");
						}

						DnsMessageBase query;
						byte[] tsigMac;
						try
						{
							query = DnsMessageBase.CreateByFlag(buffer, TsigKeySelector, null);
							tsigMac = query.TSigOptions?.Mac;
						}
						catch (Exception e)
						{
							throw new Exception("Error parsing dns query", e);
						}

						DnsMessageBase response;
						try
						{
							response = await ProcessMessageAsync(query, ProtocolType.Tcp, (IPEndPoint) client.Client.RemoteEndPoint);
						}
						catch (Exception ex)
						{
							OnExceptionThrownAsync(ex);

							response = DnsMessageBase.CreateByFlag(buffer, TsigKeySelector, null);
							response.IsQuery = false;
							response.AdditionalRecords.Clear();
							response.AuthorityRecords.Clear();
							response.ReturnCode = ReturnCode.ServerFailure;
						}

						byte[] newTsigMac;

						length = response.Encode(true, tsigMac, false, out buffer, out newTsigMac);

						if (length <= 65535)
						{
							await stream.WriteAsync(buffer, 0, length);
						}
						else
						{
							if ((response.Questions.Count == 0) || (response.Questions[0].RecordType != RecordType.Axfr))
							{
								OnExceptionThrownAsync(new ArgumentException("The length of the serialized response is greater than 65,535 bytes"));

								response = DnsMessageBase.CreateByFlag(buffer, TsigKeySelector, null);
								response.IsQuery = false;
								response.AdditionalRecords.Clear();
								response.AuthorityRecords.Clear();
								response.ReturnCode = ReturnCode.ServerFailure;

								length = response.Encode(true, tsigMac, false, out buffer, out newTsigMac);
								await stream.WriteAsync(buffer, 0, length);
							}
							else
							{
								bool isSubSequentResponse = false;

								while (true)
								{
									List<DnsRecordBase> nextPacketRecords = new List<DnsRecordBase>();

									while (length > 65535)
									{
										int lastIndex = Math.Min(500, response.AnswerRecords.Count / 2);
										int removeCount = response.AnswerRecords.Count - lastIndex;

										nextPacketRecords.InsertRange(0, response.AnswerRecords.GetRange(lastIndex, removeCount));
										response.AnswerRecords.RemoveRange(lastIndex, removeCount);

										length = response.Encode(true, tsigMac, isSubSequentResponse, out buffer, out newTsigMac);
									}

									await stream.WriteAsync(buffer, 0, length);

									if (nextPacketRecords.Count == 0)
										break;

									isSubSequentResponse = true;
									tsigMac = newTsigMac;
									response.AnswerRecords = nextPacketRecords;
									length = response.Encode(true, tsigMac, true, out buffer, out newTsigMac);
								}
							}
						}

						// Since support for multiple tsig signed messages is not finished, just close connection after response to first signed query
						if (newTsigMac != null)
							break;
					}
				}
			}
			catch (Exception ex)
			{
				OnExceptionThrownAsync(ex);
			}
			finally
			{
				try
				{
					// ReSharper disable once ConstantConditionalAccessQualifier
					client?.Close();
				}
				catch
				{
					// ignored
				}

				lock (_listenerLock)
				{
					_availableTcpListener++;
				}
				StartTcpListenerTask();
			}
		}

		private async Task<byte[]> ReadIntoBufferAsync(TcpClient client, NetworkStream stream, int count)
		{
			CancellationToken token = new CancellationTokenSource(Timeout).Token;

			byte[] buffer = new byte[count];

			if (await TryReadAsync(client, stream, buffer, count, token))
				return buffer;

			return null;
		}

		private async Task<bool> TryReadAsync(TcpClient client, NetworkStream stream, byte[] buffer, int length, CancellationToken token)
		{
			int readBytes = 0;

			while (readBytes < length)
			{
				if (token.IsCancellationRequested || !client.IsConnected())
					return false;

				readBytes += await stream.ReadAsync(buffer, readBytes, length - readBytes, token);
			}

			return true;
		}

		private void OnExceptionThrownAsync(Exception e)
		{
			if (e is ObjectDisposedException)
				return;

			Trace.TraceError("Exception in DnsServer: " + e);
			ExceptionThrown.RaiseAsync(this, new ExceptionEventArgs(e));
		}

		/// <summary>
		///   This event is fired on exceptions of the listeners. You can use it for custom logging.
		/// </summary>
		public event AsyncEventHandler<ExceptionEventArgs> ExceptionThrown;

		/// <summary>
		///   This event is fired whenever a message is received, that is not correct signed
		/// </summary>
		public event AsyncEventHandler<InvalidSignedMessageEventArgs> InvalidSignedMessageReceived;

		/// <summary>
		///   This event is fired whenever a client connects to the server
		/// </summary>
		public event AsyncEventHandler<ClientConnectedEventArgs> ClientConnected;

		/// <summary>
		///   This event is fired whenever a query is received by the server
		/// </summary>
		public event AsyncEventHandler<QueryReceivedEventArgs> QueryReceived;

		void IDisposable.Dispose()
		{
			Stop();
		}
	}
}