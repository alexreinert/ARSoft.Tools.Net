#region Copyright and License
// Copyright 2010..2017 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class DnsClientBase : IDnsClientBase
	{
		private static readonly SecureRandom _secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

		private readonly List<IPAddress> _servers;
		private readonly bool _isAnyServerMulticast;
		private readonly int _port;

        /// <summary>
        /// Map to store reusable TCP connections per server.
        /// </summary>
        internal ConcurrentDictionary<string, ReusableTcpConnection> reusableTcp;

        internal DnsClientBase(IEnumerable<IPAddress> servers, int queryTimeout, int port)
		{
			_servers = servers.OrderBy(s => s.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ToList();
			_isAnyServerMulticast = _servers.Any(s => s.IsMulticast());
			QueryTimeout = queryTimeout;
			_port = port;
            reusableTcp = new ConcurrentDictionary<string, ReusableTcpConnection>();
        }

		/// <summary>
		///   Milliseconds after which a query times out.
		/// </summary>
		public int QueryTimeout { get; }

        /// <summary>
		///   Gets or set a value indicating whether the client should reuse TCP connections.
		/// </summary>
		public bool IsReuseTcpEnabled { get; set; }

        /// <summary>
		///   Milliseconds after which a reusable TCP connection is considered IDLE and should automatically close, defaults to 5000.
		/// </summary>
		public int IdleTimeout { get; set; }

        /// <summary>
        ///   Gets or set a value indicating whether the response is validated as described in
        ///   <see
        ///     cref="!:http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">
        ///     draft-vixie-dnsext-dns0x20-00
        ///   </see>
        /// </summary>
        public bool IsResponseValidationEnabled { get; set; }

		/// <summary>
		///   Gets or set a value indicating whether the query labels are used for additional validation as described in
		///   <see
		///     cref="!:http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">
		///     draft-vixie-dnsext-dns0x20-00
		///   </see>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public bool Is0x20ValidationEnabled { get; set; }

		protected abstract int MaximumQueryMessageSize { get; }

		protected virtual bool IsUdpEnabled { get; set; }

		protected virtual bool IsTcpEnabled { get; set; }

		protected TMessage SendMessage<TMessage>(TMessage message)
			where TMessage : DnsMessageBase, new()
		{
			int messageLength;
			byte[] messageData;
			DnsServer.SelectTsigKey tsigKeySelector;
			byte[] tsigOriginalMac;

			PrepareMessage(message, out messageLength, out messageData, out tsigKeySelector, out tsigOriginalMac);

			bool sendByTcp = ((messageLength > MaximumQueryMessageSize) || message.IsTcpUsingRequested || !IsUdpEnabled);

			var endpointInfos = GetEndpointInfos();

			for (int i = 0; i < endpointInfos.Count; i++)
			{
                var endpointInfo = endpointInfos[i];
                TcpClient tcpClient = null;
                System.IO.Stream tcpStream = null;

                string reusableMapKey = string.Concat(endpointInfo.ServerAddress, endpointInfo.ServerPort);
                if (sendByTcp && this.IsReuseTcpEnabled)
                {
                    if (!this.reusableTcp.ContainsKey(reusableMapKey))
                    {
                        this.reusableTcp[reusableMapKey] = new ReusableTcpConnection();
                    }

                    ReusableTcpConnection reuse = this.reusableTcp[reusableMapKey];
                    tcpClient = reuse.Client;
                    tcpStream = reuse.Stream;
                    this.reusableTcp[reusableMapKey].LastUsed = DateTime.UtcNow;
                }

				try
				{
					IPAddress responderAddress;
                    int responderPort = 0;
					byte[] resultData = sendByTcp ? QueryByTcp(endpointInfo.ServerAddress, endpointInfo.ServerPort, messageData, messageLength, ref tcpClient, ref tcpStream, out responderAddress, out responderPort) : QueryByUdp(endpointInfo, messageData, messageLength, out responderAddress);

					if (resultData != null)
					{
						TMessage result;

						try
						{
							result = DnsMessageBase.Parse<TMessage>(resultData, tsigKeySelector, tsigOriginalMac);
						}
						catch (Exception e)
						{
							Trace.TraceError("Error on dns query: " + e);
							continue;
						}

						if (!ValidateResponse(message, result))
							continue;

						if ((result.ReturnCode == ReturnCode.ServerFailure) && (i != endpointInfos.Count - 1))
						{
							continue;
						}

						if (result.IsTcpResendingRequested)
						{
							resultData = QueryByTcp(responderAddress, responderPort, messageData, messageLength, ref tcpClient, ref tcpStream, out responderAddress, out responderPort);
							if (resultData != null)
							{
								TMessage tcpResult;

								try
								{
									tcpResult = DnsMessageBase.Parse<TMessage>(resultData, tsigKeySelector, tsigOriginalMac);
								}
								catch (Exception e)
								{
									Trace.TraceError("Error on dns query: " + e);
									continue;
								}

								if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
								{
									if (i != endpointInfos.Count - 1)
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

						bool isTcpNextMessageWaiting = result.IsTcpNextMessageWaiting(false);
						bool isSucessfullFinished = true;

						while (isTcpNextMessageWaiting)
						{
							resultData = QueryByTcp(responderAddress, responderPort, null, 0, ref tcpClient, ref tcpStream, out responderAddress, out responderPort);
							if (resultData != null)
							{
								TMessage tcpResult;

								try
								{
									tcpResult = DnsMessageBase.Parse<TMessage>(resultData, tsigKeySelector, tsigOriginalMac);
								}
								catch (Exception e)
								{
									Trace.TraceError("Error on dns query: " + e);
									isSucessfullFinished = false;
									break;
								}

								if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
								{
									isSucessfullFinished = false;
									break;
								}
								else
								{
									result.AnswerRecords.AddRange(tcpResult.AnswerRecords);
									isTcpNextMessageWaiting = tcpResult.IsTcpNextMessageWaiting(true);
								}
							}
							else
							{
								isSucessfullFinished = false;
								break;
							}
						}

						if (isSucessfullFinished)
							return result;
					}
				}
				finally
				{
					try
					{
                        if (sendByTcp && this.IsReuseTcpEnabled)
                        {
                            if (this.reusableTcp[reusableMapKey].Client == null || !ReferenceEquals(this.reusableTcp[reusableMapKey].Client, tcpClient))
                            {
                                this.reusableTcp[reusableMapKey].Client = tcpClient;
                                this.reusableTcp[reusableMapKey].Stream = tcpStream;
                            }
                        }
                        else
                        {
                            tcpStream?.Dispose();
                            tcpClient?.Close();
                        }
					}
					catch
					{
						// ignored
					}
				}
			}

			return null;
		}

		protected List<TMessage> SendMessageParallel<TMessage>(TMessage message)
			where TMessage : DnsMessageBase, new()
		{
			Task<List<TMessage>> result = SendMessageParallelAsync(message, default(CancellationToken));

			result.Wait();

			return result.Result;
		}

        private bool ValidateResponse<TMessage>(TMessage message, TMessage result)
			where TMessage : DnsMessageBase
		{
			if (IsResponseValidationEnabled)
			{
				if ((result.ReturnCode == ReturnCode.NoError) || (result.ReturnCode == ReturnCode.NxDomain))
				{
					if (message.TransactionID != result.TransactionID)
						return false;

					if ((message.Questions == null) || (result.Questions == null))
						return false;

					if ((message.Questions.Count != result.Questions.Count))
						return false;

					for (int j = 0; j < message.Questions.Count; j++)
					{
						DnsQuestion queryQuestion = message.Questions[j];
						DnsQuestion responseQuestion = result.Questions[j];

						if ((queryQuestion.RecordClass != responseQuestion.RecordClass)
						    || (queryQuestion.RecordType != responseQuestion.RecordType)
						    || (!queryQuestion.Name.Equals(responseQuestion.Name, false)))
						{
							return false;
						}
					}
				}
			}

			return true;
		}

        private void PrepareMessage<TMessage>(TMessage message, out int messageLength, out byte[] messageData, out DnsServer.SelectTsigKey tsigKeySelector, out byte[] tsigOriginalMac)
			where TMessage : DnsMessageBase, new()
		{
			if (message.TransactionID == 0)
			{
				message.TransactionID = (ushort) _secureRandom.Next(1, 0xffff);
			}

			if (Is0x20ValidationEnabled)
			{
				message.Questions.ForEach(q => q.Name = q.Name.Add0x20Bits());
			}

			messageLength = message.Encode(false, out messageData);

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
		}

		private byte[] QueryByUdp(DnsClientEndpointInfo endpointInfo, byte[] messageData, int messageLength, out IPAddress responderAddress)
		{
			using (var udpClient = new Socket(endpointInfo.LocalAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
			{
				try
				{
					udpClient.ReceiveTimeout = QueryTimeout;

					PrepareAndBindUdpSocket(endpointInfo, udpClient);

					EndPoint serverEndpoint = new IPEndPoint(endpointInfo.ServerAddress, _port);

					udpClient.SendTo(messageData, messageLength, SocketFlags.None, serverEndpoint);

					if (endpointInfo.IsMulticast)
						serverEndpoint = new IPEndPoint(udpClient.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, _port);

					byte[] buffer = new byte[65535];
					int length = udpClient.ReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None, ref serverEndpoint);

					responderAddress = ((IPEndPoint) serverEndpoint).Address;

					byte[] res = new byte[length];
					Buffer.BlockCopy(buffer, 0, res, 0, length);
					return res;
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);
					responderAddress = default(IPAddress);
					return null;
				}
			}
		}

		private void PrepareAndBindUdpSocket(DnsClientEndpointInfo endpointInfo, Socket udpClient)
		{
			if (endpointInfo.IsMulticast)
			{
				udpClient.Bind(new IPEndPoint(endpointInfo.LocalAddress, 0));
			}
			else
			{
				udpClient.Connect(endpointInfo.ServerAddress, _port);
			}
		}

		protected virtual byte[] QueryByTcp(IPAddress nameServer, int port, byte[] messageData, int messageLength, ref TcpClient tcpClient, ref System.IO.Stream tcpStream, out IPAddress responderAddress, out int responderPort)
		{
			responderAddress = nameServer;
            responderPort = port == 0 ? _port : port;

            if (!IsTcpEnabled)
				return null;

			IPEndPoint endPoint = new IPEndPoint(nameServer, port == 0 ? _port : port);

			try
			{
				if (tcpClient == null || (this.IsReuseTcpEnabled && !tcpClient.IsConnected()))
				{
                    tcpClient = new TcpClient(nameServer.AddressFamily)
					{
						ReceiveTimeout = QueryTimeout,
						SendTimeout = QueryTimeout
					};

                    if (!tcpClient.TryConnect(endPoint, QueryTimeout))
                    {
                        if (this.IsReuseTcpEnabled)
                        {
                            try
                            {
                                tcpClient.Close();
                            }
                            catch (Exception)
                            {
                            }
                        }

                        return null;
                    }

					tcpStream = tcpClient.GetStream();
				}

				int tmp = 0;
				byte[] lengthBuffer = new byte[2];

				if (messageLength > 0)
				{
					DnsMessageBase.EncodeUShort(lengthBuffer, ref tmp, (ushort) messageLength);

					tcpStream.Write(lengthBuffer, 0, 2);
					tcpStream.Write(messageData, 0, messageLength);
				}

				if (!TryRead(tcpClient, tcpStream, lengthBuffer, 2))
					return null;

				tmp = 0;
				int length = DnsMessageBase.ParseUShort(lengthBuffer, ref tmp);

				byte[] resultData = new byte[length];

				return TryRead(tcpClient, tcpStream, resultData, length) ? resultData : null;
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);
				return null;
			}
		}

		protected bool TryRead(TcpClient client, System.IO.Stream stream, byte[] buffer, int length)
		{
			int readBytes = 0;

			while (readBytes < length)
			{
				if (!client.IsConnected())
					return false;

				readBytes += stream.Read(buffer, readBytes, length - readBytes);
			}

			return true;
		}

		protected async Task<TMessage> SendMessageAsync<TMessage>(TMessage message, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			int messageLength;
			byte[] messageData;
			DnsServer.SelectTsigKey tsigKeySelector;
			byte[] tsigOriginalMac;

			PrepareMessage(message, out messageLength, out messageData, out tsigKeySelector, out tsigOriginalMac);

			bool sendByTcp = ((messageLength > MaximumQueryMessageSize) || message.IsTcpUsingRequested || !IsUdpEnabled);

			var endpointInfos = GetEndpointInfos();

			for (int i = 0; i < endpointInfos.Count; i++)
			{
				token.ThrowIfCancellationRequested();

				var endpointInfo = endpointInfos[i];
				QueryResponse resultData = null;
                string reusableMapKey = string.Concat(endpointInfo.ServerAddress, endpointInfo.ServerPort);

                try
				{
					resultData = await (sendByTcp ? QueryByTcpAsync(endpointInfo.ServerAddress, endpointInfo.ServerPort, messageData, messageLength, null, null, token) : QuerySingleResponseByUdpAsync(endpointInfo, messageData, messageLength, token));

                    if (resultData == null)
                    {
                        if (i == endpointInfos.Count - 1)
                        {
                            return null;
                        }
                        continue;
                    }
						

					TMessage result;

					try
					{
						result = DnsMessageBase.Parse<TMessage>(resultData.Buffer, tsigKeySelector, tsigOriginalMac);
					}
					catch (Exception e)
					{
						Trace.TraceError("Error on dns query: " + e);
						continue;
					}

					if (!ValidateResponse(message, result))
						continue;

					if ((result.ReturnCode != ReturnCode.NoError) && (result.ReturnCode != ReturnCode.NxDomain) && (i != endpointInfos.Count - 1))
						continue;

					if (result.IsTcpResendingRequested)
					{
						resultData = await QueryByTcpAsync(resultData.ResponderAddress, resultData.ResponderPort, messageData, messageLength, resultData.TcpClient, resultData.TcpStream, token);
						if (resultData != null)
						{
							TMessage tcpResult;

							try
							{
								tcpResult = DnsMessageBase.Parse<TMessage>(resultData.Buffer, tsigKeySelector, tsigOriginalMac);
							}
							catch (Exception e)
							{
								Trace.TraceError("Error on dns query: " + e);
								return null;
							}

							if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
							{
								return result;
							}
							else
							{
								result = tcpResult;
							}
						}
					}

					bool isTcpNextMessageWaiting = result.IsTcpNextMessageWaiting(false);
					bool isSucessfullFinished = true;

					while (isTcpNextMessageWaiting)
					{
						// ReSharper disable once PossibleNullReferenceException
						resultData = await QueryByTcpAsync(resultData.ResponderAddress, resultData.ResponderPort, null, 0, resultData.TcpClient, resultData.TcpStream, token);
						if (resultData != null)
						{
							TMessage tcpResult;

							try
							{
								tcpResult = DnsMessageBase.Parse<TMessage>(resultData.Buffer, tsigKeySelector, tsigOriginalMac);
							}
							catch (Exception e)
							{
								Trace.TraceError("Error on dns query: " + e);
								isSucessfullFinished = false;
								break;
							}

							if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
							{
								isSucessfullFinished = false;
								break;
							}
							else
							{
								result.AnswerRecords.AddRange(tcpResult.AnswerRecords);
								isTcpNextMessageWaiting = tcpResult.IsTcpNextMessageWaiting(true);
							}
						}
						else
						{
							isSucessfullFinished = false;
							break;
						}
					}

					if (isSucessfullFinished)
						return result;
				}
				finally
				{
					if (resultData != null)
					{
                        if (sendByTcp && this.IsReuseTcpEnabled)
                        {
                            if (this.reusableTcp[reusableMapKey].Client == null || !ReferenceEquals(this.reusableTcp[reusableMapKey].Client, resultData.TcpClient))
                            {
                                this.reusableTcp[reusableMapKey].Client = resultData.TcpClient;
                                this.reusableTcp[reusableMapKey].Stream = resultData.TcpStream;
                            }
                        }
                        else
                        {
                            try
                            {
                                resultData.TcpStream?.Dispose();
                                resultData.TcpClient?.Close();
                            }
                            catch
                            {
                                // ignored
                            }
                        }
					}
				}
			}

			return null;
		}

		private async Task<QueryResponse> QuerySingleResponseByUdpAsync(DnsClientEndpointInfo endpointInfo, byte[] messageData, int messageLength, CancellationToken token)
		{
			try
			{
				if (endpointInfo.IsMulticast)
				{
					using (UdpClient udpClient = new UdpClient(new IPEndPoint(endpointInfo.LocalAddress, 0)))
					{
						IPEndPoint serverEndpoint = new IPEndPoint(endpointInfo.ServerAddress, _port);
						await udpClient.SendAsync(messageData, messageLength, serverEndpoint);

						udpClient.Client.SendTimeout = QueryTimeout;
						udpClient.Client.ReceiveTimeout = QueryTimeout;

						UdpReceiveResult response = await udpClient.ReceiveAsync(QueryTimeout, token);
						return new QueryResponse(response.Buffer, response.RemoteEndPoint.Address);
					}
				}
				else
				{
					using (UdpClient udpClient = new UdpClient(endpointInfo.LocalAddress.AddressFamily))
					{
						udpClient.Connect(endpointInfo.ServerAddress, _port);

						udpClient.Client.SendTimeout = QueryTimeout;
						udpClient.Client.ReceiveTimeout = QueryTimeout;

						await udpClient.SendAsync(messageData, messageLength);

						UdpReceiveResult response = await udpClient.ReceiveAsync(QueryTimeout, token);
						return new QueryResponse(response.Buffer, response.RemoteEndPoint.Address);
					}
				}
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);
				return null;
			}
		}

		protected class QueryResponse
		{
			public byte[] Buffer { get; }
			public IPAddress ResponderAddress { get; }
            public int ResponderPort { get; }

            public TcpClient TcpClient { get; }
			public System.IO.Stream TcpStream { get; }

			public QueryResponse(byte[] buffer, IPAddress responderAddress, int responderPort = 0)
			{
				Buffer = buffer;
				ResponderAddress = responderAddress;
                ResponderPort = responderPort;
			}

			public QueryResponse(byte[] buffer, IPAddress responderAddress, TcpClient tcpClient, System.IO.Stream tcpStream, int responderPort = 0)
			{
				Buffer = buffer;
				ResponderAddress = responderAddress;
                ResponderPort = responderPort;
                TcpClient = tcpClient;
				TcpStream = tcpStream;
			}
		}

		protected virtual async Task<QueryResponse> QueryByTcpAsync(IPAddress nameServer, int port, byte[] messageData, int messageLength, TcpClient tcpClient, System.IO.Stream tcpStream, CancellationToken token)
		{
			if (!IsTcpEnabled)
				return null;

            string reusableMapKey = string.Concat(nameServer, port);
            if (tcpClient == null && this.IsReuseTcpEnabled)
            {
                if (!this.reusableTcp.ContainsKey(reusableMapKey))
                {
                    this.reusableTcp[reusableMapKey] = new ReusableTcpConnection();
                }

                ReusableTcpConnection reuse = this.reusableTcp[reusableMapKey];
                tcpClient = reuse.Client;
                tcpStream = reuse.Stream;
                this.reusableTcp[reusableMapKey].LastUsed = DateTime.UtcNow;
            }

            int responderPort = port == 0 ? _port : port;
            try
			{
				if (tcpClient == null || (this.IsReuseTcpEnabled && !tcpClient.IsConnected()))
				{
                    tcpClient = new TcpClient(nameServer.AddressFamily)
					{
						ReceiveTimeout = QueryTimeout,
						SendTimeout = QueryTimeout
					};

					if (!await tcpClient.TryConnectAsync(nameServer, responderPort, QueryTimeout, token))
					{
                        if (this.IsReuseTcpEnabled)
                        {
                            try
                            {
                                tcpClient.Close();
                            }
                            catch (Exception)
                            {
                            }
                        }

                        return null;
					}

					tcpStream = tcpClient.GetStream();
				}

				int tmp = 0;
				byte[] lengthBuffer = new byte[2];

				if (messageLength > 0)
				{
					DnsMessageBase.EncodeUShort(lengthBuffer, ref tmp, (ushort) messageLength);

					await tcpStream.WriteAsync(lengthBuffer, 0, 2, token);
					await tcpStream.WriteAsync(messageData, 0, messageLength, token);
				}

				if (!await TryReadAsync(tcpClient, tcpStream, lengthBuffer, 2, token))
					return null;

				tmp = 0;
				int length = DnsMessageBase.ParseUShort(lengthBuffer, ref tmp);

				byte[] resultData = new byte[length];

				return await TryReadAsync(tcpClient, tcpStream, resultData, length, token) ? new QueryResponse(resultData, nameServer, tcpClient, tcpStream, responderPort) : null;
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);
				return null;
			}
		}

		protected async Task<bool> TryReadAsync(TcpClient client, System.IO.Stream stream, byte[] buffer, int length, CancellationToken token)
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

		protected async Task<List<TMessage>> SendMessageParallelAsync<TMessage>(TMessage message, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			int messageLength;
			byte[] messageData;
			DnsServer.SelectTsigKey tsigKeySelector;
			byte[] tsigOriginalMac;

			PrepareMessage(message, out messageLength, out messageData, out tsigKeySelector, out tsigOriginalMac);

			if (messageLength > MaximumQueryMessageSize)
				throw new ArgumentException("Message exceeds maximum size");

			if (message.IsTcpUsingRequested)
				throw new NotSupportedException("Using tcp is not supported in parallel mode");

			BlockingCollection<TMessage> results = new BlockingCollection<TMessage>();
			CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

			// ReSharper disable once ReturnValueOfPureMethodIsNotUsed
			GetEndpointInfos().Select(x => SendMessageParallelAsync(x, message, messageData, messageLength, tsigKeySelector, tsigOriginalMac, results, CancellationTokenSource.CreateLinkedTokenSource(token, cancellationTokenSource.Token).Token)).ToArray();

			await Task.Delay(QueryTimeout, token);

			cancellationTokenSource.Cancel();

			return results.ToList();
		}

		private async Task SendMessageParallelAsync<TMessage>(DnsClientEndpointInfo endpointInfo, TMessage message, byte[] messageData, int messageLength, DnsServer.SelectTsigKey tsigKeySelector, byte[] tsigOriginalMac, BlockingCollection<TMessage> results, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			using (UdpClient udpClient = new UdpClient(new IPEndPoint(endpointInfo.LocalAddress, 0)))
			{
				IPEndPoint serverEndpoint = new IPEndPoint(endpointInfo.ServerAddress, _port);
				await udpClient.SendAsync(messageData, messageLength, serverEndpoint);

				udpClient.Client.SendTimeout = QueryTimeout;
				udpClient.Client.ReceiveTimeout = QueryTimeout;

				while (true)
				{
					TMessage result;
					UdpReceiveResult response = await udpClient.ReceiveAsync(Int32.MaxValue, token);

					try
					{
						result = DnsMessageBase.Parse<TMessage>(response.Buffer, tsigKeySelector, tsigOriginalMac);
					}
					catch (Exception e)
					{
						Trace.TraceError("Error on dns query: " + e);
						continue;
					}

					if (!ValidateResponse(message, result))
						continue;

					if (result.ReturnCode == ReturnCode.ServerFailure)
						continue;

					results.Add(result, token);

					if (token.IsCancellationRequested)
						break;
				}
			}
		}

		internal virtual List<DnsClientEndpointInfo> GetEndpointInfos()
		{
			List<DnsClientEndpointInfo> endpointInfos;
			if (_isAnyServerMulticast)
			{
				var localIPs = NetworkInterface.GetAllNetworkInterfaces()
					.Where(n => n.SupportsMulticast && (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
					.SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => a.Address))
					.Where(a => !IPAddress.IsLoopback(a) && ((a.AddressFamily == AddressFamily.InterNetwork) || a.IsIPv6LinkLocal))
					.ToList();

				endpointInfos = _servers
					.SelectMany(
						s =>
						{
							if (s.IsMulticast())
							{
								return localIPs
									.Where(l => l.AddressFamily == s.AddressFamily)
									.Select(
										l => new DnsClientEndpointInfo
										{
											IsMulticast = true,
											ServerAddress = s,
											LocalAddress = l
										});
							}
							else
							{
								return new[]
								{
									new DnsClientEndpointInfo
									{
										IsMulticast = false,
										ServerAddress = s,
										LocalAddress = s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any
									}
								};
							}
						}).ToList();
			}
			else
			{
				endpointInfos = _servers
					.Where(x => IsIPv6Enabled || (x.AddressFamily == AddressFamily.InterNetwork))
					.Select(
						s => new DnsClientEndpointInfo
						{
							IsMulticast = false,
							ServerAddress = s,
							LocalAddress = s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any
						}
					).ToList();
			}
			return endpointInfos;
		}

		protected static bool IsIPv6Enabled { get; } = IsAnyIPv6Configured();

        protected static readonly IPAddress _ipvMappedNetworkAddress = IPAddress.Parse("0:0:0:0:0:FFFF::");

        protected static bool IsAnyIPv6Configured()
		{
			return NetworkInterface.GetAllNetworkInterfaces()
				.Where(n => (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
				.SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => a.Address))
				.Any(a => !IPAddress.IsLoopback(a) && (a.AddressFamily == AddressFamily.InterNetworkV6) && !a.IsIPv6LinkLocal && !a.IsIPv6Teredo && !a.GetNetworkAddress(96).Equals(_ipvMappedNetworkAddress));
		}
	}
}
