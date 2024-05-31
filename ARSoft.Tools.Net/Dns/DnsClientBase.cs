#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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
using static ARSoft.Tools.Net.Dns.DnsServer;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class DnsClientBase : IDisposable
	{
		private class ReceivedMessage<TMessage>
		{
			public IPEndPoint ResponderAddress { get; }
			public IPEndPoint LocalAddress { get; }
			public TMessage Message { get; }

			public ReceivedMessage(IPEndPoint responderAddress, IPEndPoint localAddress, TMessage message)
			{
				ResponderAddress = responderAddress;
				LocalAddress = localAddress;
				Message = message;
			}
		}

		private static readonly SecureRandom _secureRandom = new(new CryptoApiRandomGenerator());

		private readonly List<DnsClientEndpointInfo> _endpointInfos;

		private readonly IClientTransport[] _transports;
		private readonly bool _disposeTransports;

		internal DnsClientBase(IEnumerable<IPAddress> servers, int queryTimeout, IClientTransport[] transports, bool disposeTransports)
		{
			QueryTimeout = queryTimeout;

			_transports = transports;
			_disposeTransports = disposeTransports;

			_endpointInfos = GetEndpointInfos(servers);
		}

		/// <summary>
		///   Milliseconds after which a query times out.
		/// </summary>
		public int QueryTimeout { get; }

		/// <summary>
		///   Gets or set a value indicating whether the response is validated as described in
		///   <a href="http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">draft-vixie-dnsext-dns0x20-00</a>
		/// </summary>
		public bool IsResponseValidationEnabled { get; set; }

		/// <summary>
		///   Gets or set a value indicating whether the query labels are used for additional validation as described in
		///   <a href="http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">draft-vixie-dnsext-dns0x20-00</a>
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public bool Is0x20ValidationEnabled { get; set; }

		protected TMessage? SendMessage<TMessage>(TMessage query)
			where TMessage : DnsMessageBase, new()
		{
			return SendMessageAsync<TMessage>(query, CancellationToken.None).GetAwaiter().GetResult();
		}

		protected List<TMessage> SendMessageParallel<TMessage>(TMessage message)
			where TMessage : DnsMessageBase, new()
		{
			return SendMessageParallelAsync(message, default).GetAwaiter().GetResult();
		}

		private bool ValidateResponse<TMessage>(TMessage message, TMessage response)
			where TMessage : DnsMessageBase
		{
			if (IsResponseValidationEnabled)
			{
				message.ValidateResponse(response);
			}

			return true;
		}

		private DnsRawPackage PrepareMessage<TMessage>(TMessage message, out SelectTsigKey? tsigKeySelector, out byte[]? tsigOriginalMac)
			where TMessage : DnsMessageBase, new()
		{
			if (message.TransactionID == 0)
			{
				message.TransactionID = (ushort) _secureRandom.Next(1, 0xffff);
			}

			if (Is0x20ValidationEnabled)
			{
				message.Add0x20Bits();
			}

			var package = message.Encode(null, false, out tsigOriginalMac);

			if (message.TSigOptions != null)
			{
				tsigKeySelector = (_, _, _) => message.TSigOptions!.KeyData;
			}
			else
			{
				tsigKeySelector = null;
			}

			return package;
		}

		protected async Task<TMessage?> SendMessageAsync<TMessage>(TMessage query, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			var package = PrepareMessage(query, out var tsigKeySelector, out var tsigOriginalMac);

			TMessage? response = null;

			foreach (var connectionTask in GetConnectionTasks(package, query.IsReliableSendingRequested, token))
			{
				IClientConnection? connection = null;

				try
				{
					connection = await connectionTask;

					if (connection == null)
						continue;

					var receivedMessage = await SendMessageAsync<TMessage>(package, connection, tsigKeySelector, tsigOriginalMac, token);

					if ((receivedMessage != null) && ValidateResponse(query, receivedMessage.Message))
					{
						connection.RestartIdleTimeout(receivedMessage.Message.GetEDnsKeepAliveTimeout());

						if (receivedMessage.Message.ReturnCode == ReturnCode.ServerFailure)
						{
							response = receivedMessage.Message;
							continue;
						}

						if (!receivedMessage.Message.IsReliableResendingRequested)
							return receivedMessage.Message;

						var resendTransport = _transports.FirstOrDefault(t => t.SupportsReliableTransfer && t.MaximumAllowedQuerySize <= package.Length && t != connection.Transport);

						if (resendTransport != null)
						{
							using (var resendConnection = await resendTransport.ConnectAsync(new DnsClientEndpointInfo(false, receivedMessage.ResponderAddress.Address, receivedMessage.LocalAddress.Address), QueryTimeout, token))
							{
								if (resendConnection == null)
								{
									response = receivedMessage.Message;
								}
								else
								{
									var resendResponse = await SendMessageAsync<TMessage>(package, resendConnection, tsigKeySelector, tsigOriginalMac, token);

									if ((resendResponse != null)
									    && ValidateResponse(query, resendResponse.Message)
									    && ((resendResponse.Message.ReturnCode != ReturnCode.ServerFailure)))
									{
										resendConnection.RestartIdleTimeout(receivedMessage.Message.GetEDnsKeepAliveTimeout());
										return resendResponse.Message;
									}
									else
									{
										resendConnection.MarkFaulty();
										response = receivedMessage.Message;
									}
								}
							}
						}
					}
					else
					{
						connection.MarkFaulty();
					}
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);
					connection?.MarkFaulty();
				}
				finally
				{
					connection?.Dispose();
				}
			}

			return response;
		}

		private IEnumerable<Task<IClientConnection?>> GetConnectionTasks(DnsRawPackage package, bool isReliableTransportRequested, CancellationToken token)
		{
			foreach (var transport in _transports)
			{
				if (transport.SupportsPooledConnections
				    && package.Length <= transport.MaximumAllowedQuerySize
				    && (!isReliableTransportRequested || transport.SupportsReliableTransfer))
				{
					foreach (var endpointInfo in _endpointInfos)
					{
						yield return transport.GetPooledConnectionAsync(endpointInfo, token);
					}
				}
			}

			foreach (var transport in _transports)
			{
				if (package.Length <= transport.MaximumAllowedQuerySize
				    && (!isReliableTransportRequested || transport.SupportsReliableTransfer))
				{
					foreach (var endpointInfo in _endpointInfos)
					{
						yield return transport.ConnectAsync(endpointInfo, QueryTimeout, token);
					}
				}
			}
		}

		private async Task<ReceivedMessage<TMessage>?> SendMessageAsync<TMessage>(DnsRawPackage package, IClientConnection connection, SelectTsigKey? tsigKeySelector, byte[]? tsigOriginalMac, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			if (!await connection.SendAsync(package, token))
				return null;

			var resultData = await connection.ReceiveAsync(package.MessageIdentification, token);

			if (resultData == null)
				return null;

			var response = DnsMessageBase.Parse<TMessage>(resultData.ToArraySegment(false), tsigKeySelector, tsigOriginalMac);

			var isNextMessageWaiting = response.IsNextMessageWaiting(false);

			while (isNextMessageWaiting)
			{
				resultData = await connection.ReceiveAsync(package.MessageIdentification, token);

				if (resultData == null)
					return null;

				var nextResult = DnsMessageBase.Parse<TMessage>(resultData.ToArraySegment(false), tsigKeySelector, tsigOriginalMac);

				if (nextResult.ReturnCode == ReturnCode.ServerFailure)
					return null;

				response.AddSubsequentResponse(nextResult);
				isNextMessageWaiting = nextResult.IsNextMessageWaiting(true);
			}

			return new ReceivedMessage<TMessage>(resultData.RemoteEndpoint, resultData.LocalEndpoint, response);
		}

		protected async Task<List<TMessage>> SendMessageParallelAsync<TMessage>(TMessage message, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			var package = PrepareMessage(message, out var tsigKeySelector, out var tsigOriginalMac);

			var multicastTransport = _transports.FirstOrDefault(t => t.SupportsMulticastTransfer);

			if (multicastTransport == null)
				return new List<TMessage>();

			if (package.Length > multicastTransport.MaximumAllowedQuerySize)
				throw new ArgumentException("Message exceeds maximum size");

			if (message.IsReliableSendingRequested)
				throw new NotSupportedException("Sending reliable messages is not supported in multicast mode");

			var results = new BlockingCollection<TMessage>();
			var cancellationTokenSource = new CancellationTokenSource();

			cancellationTokenSource.CancelAfter(QueryTimeout);

			var tasks = _endpointInfos.Select(x => SendMessageParallelAsync(multicastTransport, x, message, package, tsigKeySelector, tsigOriginalMac, results, CancellationTokenSource.CreateLinkedTokenSource(token, cancellationTokenSource.Token).Token)).ToArray();

			await Task.WhenAll(tasks);

			return results.ToList();
		}

		private async Task SendMessageParallelAsync<TMessage>(IClientTransport transport, DnsClientEndpointInfo endpointInfo, TMessage query, DnsRawPackage package, SelectTsigKey? tsigKeySelector, byte[]? tsigOriginalMac, BlockingCollection<TMessage> results, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			using (var connection = await transport.ConnectAsync(endpointInfo, QueryTimeout, token))
			{
				if (connection == null)
					return;

				if (!await connection.SendAsync(package, token))
					return;

				while (true)
				{
					if (token.IsCancellationRequested)
						break;

					var response = await connection.ReceiveAsync(package.MessageIdentification, token);

					if (response == null)
						continue;

					TMessage result;

					try
					{
						result = DnsMessageBase.Parse<TMessage>(response.ToArraySegment(false), tsigKeySelector, tsigOriginalMac);
					}
					catch (Exception e)
					{
						Trace.TraceError("Error on dns query: " + e);
						continue;
					}

					if (!ValidateResponse(query, result))
						continue;

					if (result.ReturnCode == ReturnCode.ServerFailure)
						continue;

					var resendTransport = _transports.FirstOrDefault(t => t.SupportsReliableTransfer && t.MaximumAllowedQuerySize <= package.Length && t != connection.Transport);
					if (result.IsReliableResendingRequested && resendTransport != null)
					{
						ResendParallelMessageAsync(resendTransport, new DnsClientEndpointInfo(false, response.RemoteEndpoint.Address, response.LocalEndpoint.Address), query, package, tsigKeySelector, tsigOriginalMac, results, token).Start();
					}
					else
					{
						results.Add(result, token);
					}
				}
			}
		}

		private async Task ResendParallelMessageAsync<TMessage>(IClientTransport transport, DnsClientEndpointInfo endpointInfo, TMessage query, DnsRawPackage package, SelectTsigKey? tsigKeySelector, byte[]? tsigOriginalMac, BlockingCollection<TMessage> results, CancellationToken token)
			where TMessage : DnsMessageBase, new()
		{
			if (endpointInfo.IsMulticast && !transport.SupportsMulticastTransfer)
				return;

			IClientConnection? connection = null;

			try
			{
				connection = await transport.ConnectAsync(endpointInfo, QueryTimeout, token);

				var response = await SendMessageAsync<TMessage>(package, connection!, tsigKeySelector, tsigOriginalMac, token);

				if ((response != null)
				    && ValidateResponse(query, response.Message))
				{
					results.Add(response.Message, token);
				}
				else
				{
					connection?.MarkFaulty();
				}
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);
				connection?.MarkFaulty();
			}
			finally
			{
				connection?.Dispose();
			}
		}

		private List<DnsClientEndpointInfo> GetEndpointInfos(IEnumerable<IPAddress> servers)
		{
			servers = servers.OrderBy(s => s.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ToList();

			List<DnsClientEndpointInfo> endpointInfos;
			if (servers.Any(s => s.IsMulticast()))
			{
				var localIPs = NetworkInterface.GetAllNetworkInterfaces()
					.Where(n => n.SupportsMulticast && (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
					.SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => a.Address))
					.Where(a => !IPAddress.IsLoopback(a) && ((a.AddressFamily == AddressFamily.InterNetwork) || a.IsIPv6LinkLocal))
					.ToList();

				endpointInfos = servers
					.SelectMany(
						s =>
						{
							if (s.IsMulticast())
							{
								return localIPs
									.Where(l => l.AddressFamily == s.AddressFamily)
									.Select(l => new DnsClientEndpointInfo(true, s, l));
							}
							else
							{
								return new[]
								{
									new DnsClientEndpointInfo(false, s, s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any)
								};
							}
						}).ToList();
			}
			else
			{
				endpointInfos = servers
					.Where(x => IsIPv6Enabled || (x.AddressFamily == AddressFamily.InterNetwork))
					.Select(s => new DnsClientEndpointInfo(false, s, s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any))
					.ToList();
			}

			return endpointInfos;
		}

		private static bool IsIPv6Enabled { get; } = IsAnyIPv6Configured();

		private static readonly IPAddress _ipvMappedNetworkAddress = IPAddress.Parse("0:0:0:0:0:FFFF::");

		private static bool IsAnyIPv6Configured()
		{
			return NetworkInterface.GetAllNetworkInterfaces()
				.Where(n => (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
				.SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => a.Address))
				.Any(a => !IPAddress.IsLoopback(a) && (a.AddressFamily == AddressFamily.InterNetworkV6) && !a.IsIPv6LinkLocal && !a.IsIPv6Teredo && !a.GetNetworkAddress(96).Equals(_ipvMappedNetworkAddress));
		}

		void IDisposable.Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool isDisposing)
		{
			if (_disposeTransports)
			{
				foreach (var transport in _transports)
				{
					transport.Dispose();
				}
			}
		}

		~DnsClientBase()
		{
			Dispose(false);
		}
	}
}