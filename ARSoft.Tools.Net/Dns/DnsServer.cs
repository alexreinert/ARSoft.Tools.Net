#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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
		/// <param name="isTruncated"> A value indicating if the MAC was truncated </param>
		/// <param name="keyName"> The keyname which is used in the message </param>
		/// <returns> Binary representation of the key </returns>
		public delegate byte[]? SelectTsigKey(TSigAlgorithm algorithm, bool isTruncated, DomainName keyName);

		public const int DEFAULT_DNS_PORT = 53;

		private readonly IServerTransport[] _transports;
		private Task[] _transportTasks = Array.Empty<Task>();
		private CancellationTokenSource _serverCancellationTokenSource = new();

		/// <summary>
		///   Method that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		public SelectTsigKey? TsigKeySelector;

		/// <summary>
		///   Creates a new dns server instance which will listen on UDP and TCP on all available interfaces
		/// </summary>
		/// <param name="timeout"> The timeout in milliseconds </param>
		/// <param name="keepAlive"> The keepalive period in milliseconds to wait for additional queries on the same connection </param>
		public DnsServer(int timeout = 5000, int keepAlive = 120000)
			: this(
				new UdpServerTransport(IPAddress.IPv6Any, timeout),
				new TcpServerTransport(IPAddress.IPv6Any, timeout, keepAlive)) { }

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="transports"> Transports, which should be used </param>
		public DnsServer(params IServerTransport[] transports)
		{
			if (transports.Length == 0)
				throw new ArgumentException("At least one transport must be given");

			_transports = transports;
		}

		/// <summary>
		///   Starts the server
		/// </summary>
		public void Start()
		{
			foreach (var transport in _transports)
			{
				transport.Bind();
			}

			_serverCancellationTokenSource = new CancellationTokenSource();

			_transportTasks = _transports.Select<IServerTransport, Task>(t =>
				Task.Run(() => ConnectionLoopAsync(t, _serverCancellationTokenSource.Token), _serverCancellationTokenSource.Token)).ToArray();
		}

		/// <summary>
		///   Stops the server
		/// </summary>
		public void Stop()
		{
			_serverCancellationTokenSource.Cancel();

			Task.WaitAll(_transportTasks);

			foreach (var transport in _transports)
			{
				transport.Close();
			}
		}

		private async void ConnectionLoopAsync(IServerTransport transport, CancellationToken token)
		{
			while (!token.IsCancellationRequested)
			{
				var connection = await transport.AcceptConnectionAsync(token);

				if (connection == null)
					continue;

#pragma warning disable CS4014
				Task.Run(() => ProcessConnectionAsync(connection, token), token);
#pragma warning restore CS4014
			}
		}

		private async void ProcessConnectionAsync(IServerConnection connection, CancellationToken token)
		{
			var clientConnectedEventArgs = new ClientConnectedEventArgs(connection.Transport.TransportProtocol, connection.RemoteEndPoint, connection.LocalEndPoint);
			await ClientConnected.RaiseAsync(this, clientConnectedEventArgs);

			if (clientConnectedEventArgs.RefuseConnect)
				return;

			try
			{
				while (connection.CanRead)
				{
					var queryPackage = await connection.ReceiveAsync(token);

					if (queryPackage == null)
						break;

					DnsMessageBase query;
					byte[]? tsigMac;
					try
					{
						query = DnsMessageBase.CreateByFlag(queryPackage.ToArraySegment(false), TsigKeySelector, null);
						tsigMac = query.TSigOptions?.Mac;
					}
					catch (Exception e)
					{
						throw new Exception("Error parsing dns query", e);
					}

					DnsMessageBase response;
					try
					{
						response = await ProcessMessageAsync(query, connection.Transport.TransportProtocol == TransportProtocol.Udp ? ProtocolType.Udp : ProtocolType.Tcp, connection.RemoteEndPoint!);
					}
					catch (Exception ex)
					{
						OnExceptionThrownAsync(ex);

						response = query.CreateFailureResponse();
					}

					var responsePackage = response.Encode(tsigMac, false, out var newTsigMac);

					if (responsePackage.Length <= connection.Transport.DefaultAllowedResponseSize)
					{
						await connection.SendAsync(responsePackage, token);
					}
					else
					{
						if (response.AllowMultipleResponses)
						{
							var isSubSequentResponse = false;

							foreach (var partialResponse in response.SplitResponse())
							{
								responsePackage = partialResponse.Encode(tsigMac, isSubSequentResponse, out newTsigMac);
								await connection.SendAsync(responsePackage, token);
								isSubSequentResponse = true;
								tsigMac = newTsigMac;
							}
						}
						else if (connection.Transport.AllowTruncatedResponses)
						{
							#region Truncating
							if (response is DnsMessage message)
							{
								int maxLength = connection.Transport.DefaultAllowedResponseSize;
								if (query.IsEDnsEnabled && message.IsEDnsEnabled)
								{
									maxLength = Math.Max(connection.Transport.DefaultAllowedResponseSize, (int) message.EDnsOptions!.UdpPayloadSize);
								}

								while (responsePackage.Length > maxLength)
								{
									// First step: remove data from additional records except the opt record
									if ((message.IsEDnsEnabled && (message.AdditionalRecords.Count > 1)) || (!message.IsEDnsEnabled && (message.AdditionalRecords.Count > 0)))
									{
										for (var i = message.AdditionalRecords.Count - 1; i >= 0; i--)
										{
											if (message.AdditionalRecords[i].RecordType != RecordType.Opt)
											{
												message.AdditionalRecords.RemoveAt(i);
											}
										}

										responsePackage = message.Encode(tsigMac);
										continue;
									}

									var savedLength = 0;
									if (message.AuthorityRecords.Count > 0)
									{
										for (var i = message.AuthorityRecords.Count - 1; i >= 0; i--)
										{
											savedLength += message.AuthorityRecords[i].MaximumLength;
											message.AuthorityRecords.RemoveAt(i);

											if ((responsePackage.Length - savedLength) < maxLength)
											{
												break;
											}
										}

										message.IsTruncated = true;

										responsePackage = message.Encode(tsigMac);
										continue;
									}

									if (message.AnswerRecords.Count > 0)
									{
										for (var i = message.AnswerRecords.Count - 1; i >= 0; i--)
										{
											savedLength += message.AnswerRecords[i].MaximumLength;
											message.AnswerRecords.RemoveAt(i);

											if ((responsePackage.Length - savedLength) < maxLength)
											{
												break;
											}
										}

										message.IsTruncated = true;

										responsePackage = message.Encode(tsigMac);
										continue;
									}

									if (message.Questions.Count > 0)
									{
										for (var i = message.Questions.Count - 1; i >= 0; i--)
										{
											savedLength += message.Questions[i].MaximumLength;
											message.Questions.RemoveAt(i);

											if ((responsePackage.Length - savedLength) < maxLength)
											{
												break;
											}
										}

										message.IsTruncated = true;

										responsePackage = message.Encode(tsigMac);
									}
								}
							}
							#endregion

							await connection.SendAsync(responsePackage, token);
						}
						else
						{
							OnExceptionThrownAsync(new ArgumentException("The length of the serialized response is greater than 65,535 bytes"));

							response = query.CreateFailureResponse();

							responsePackage = response.Encode(tsigMac, false, out newTsigMac);
							await connection.SendAsync(responsePackage, token);
						}
					}

					// Since support for multiple tsig signed messages is not finished, just close connection after response to first signed query
					if (newTsigMac != null)
						break;
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
					connection?.Dispose();
				}
				catch
				{
					// ignored
				}
			}
		}

		private async Task<DnsMessageBase> ProcessMessageAsync(DnsMessageBase query, ProtocolType protocolType, IPEndPoint remoteEndpoint)
		{
			if (query.TSigOptions != null)
			{
				switch (query.TSigOptions.ValidationResult)
				{
					case ReturnCode.FormatError:
					{
						var response = query.CreateFailureResponse();
						response.ReturnCode = ReturnCode.FormatError;
						response.TSigOptions = null;

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, protocolType, remoteEndpoint));
#pragma warning restore 4014

						return response;
					}

					case ReturnCode.BadKey:
					case ReturnCode.BadSig:
					case ReturnCode.BadTrunc:
					{
						var response = query.CreateFailureResponse();
						response.ReturnCode = ReturnCode.NotAuthoritive;
						response.TSigOptions = new TSigRecord(query.TSigOptions.Name, query.TSigOptions.Algorithm, query.TSigOptions.TimeSigned, query.TSigOptions.Fudge, query.TSigOptions.OriginalID, query.TSigOptions.ValidationResult, null, null);

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, protocolType, remoteEndpoint));
#pragma warning restore 4014

						return response;
					}

					case ReturnCode.BadTime:
					{
						var otherData = new byte[6];
						var tmp = 0;
						TSigRecord.EncodeDateTime(otherData, ref tmp, DateTime.Now);

						var response = query.CreateFailureResponse();
						response.ReturnCode = ReturnCode.NotAuthoritive;
						response.TSigOptions = new TSigRecord(query.TSigOptions.Name, query.TSigOptions.Algorithm, query.TSigOptions.TimeSigned, query.TSigOptions.Fudge, query.TSigOptions.OriginalID, query.TSigOptions.ValidationResult, otherData, null);

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, protocolType, remoteEndpoint));
#pragma warning restore 4014

						return response;
					}
				}
			}

			QueryReceivedEventArgs eventArgs = new QueryReceivedEventArgs(query, protocolType, remoteEndpoint);
			await QueryReceived.RaiseAsync(this, eventArgs);
			return eventArgs.Response ?? query.CreateFailureResponse();
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
		public event AsyncEventHandler<ExceptionEventArgs>? ExceptionThrown;

		/// <summary>
		///   This event is fired whenever a message is received, that is not correct signed
		/// </summary>
		public event AsyncEventHandler<InvalidSignedMessageEventArgs>? InvalidSignedMessageReceived;

		/// <summary>
		///   This event is fired whenever a client connects to the server
		/// </summary>
		public event AsyncEventHandler<ClientConnectedEventArgs>? ClientConnected;

		/// <summary>
		///   This event is fired whenever a query is received by the server
		/// </summary>
		public event AsyncEventHandler<QueryReceivedEventArgs>? QueryReceived;

		void IDisposable.Dispose()
		{
			Stop();
		}
	}
}