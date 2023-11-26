#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
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

using System.Collections.Concurrent;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ARSoft.Tools.Net.Dns;

public class HttpsServerTransport : IServerTransport
{
	private readonly WebApplication _app;

	private readonly Channel<HttpsServerConnection> _connectionQueue = Channel.CreateUnbounded<HttpsServerConnection>();

	public HttpsServerTransport(X509Certificate2 cert, int port = 443)
	{
		var builder = WebApplication.CreateBuilder();

		builder.Configuration.AddInMemoryCollection(new Dictionary<string, string>());
		builder.Host.ConfigureHostConfiguration(c => { });
		builder.Host.ConfigureAppConfiguration(c => { });
		builder.WebHost.ConfigureKestrel(kestrel =>
		{
			kestrel.ConfigureHttpsDefaults(https =>
			{
				https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
				https.ServerCertificate = cert;
			});
			kestrel.ListenAnyIP(port, listen => listen.UseHttps());
		});
		builder.Logging.ClearProviders();

		_app = builder.Build();
		_app.UseStatusCodePages();
		_app.MapDnsOverHttps("dns-query", HandleRequest);
	}

	private async Task<DnsRawPackage?> HandleRequest(DnsReceivedRawPackage query, HttpContext context, CancellationToken token)
	{
		var tcs = new TaskCompletionSource<DnsRawPackage?>();
		var connection = new HttpsServerConnection(this, query, tcs);
		await _connectionQueue.Writer.WriteAsync(connection, token);
		return await tcs.Task.WaitAsync(token);
	}

	public void Dispose()
	{
		_app.TryDispose();
	}

	public ushort DefaultAllowedResponseSize => ushort.MaxValue;
	public bool SupportsMultipleResponses => false;
	public bool AllowTruncatedResponses => false;

	public TransportProtocol TransportProtocol => TransportProtocol.Https;

	public void Bind()
	{
		_app.RunAsync();
	}

	public void Close()
	{
		_app.StopAsync();
	}

	public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
	{
		await _connectionQueue.Reader.WaitToReadAsync(token);
		return _connectionQueue.Reader.TryRead(out var connection) ? connection : null;
	}

	private class HttpsServerConnection : IServerConnection
	{
		private readonly DnsReceivedRawPackage _query;
		private readonly TaskCompletionSource<DnsRawPackage?> _tcs;

		public HttpsServerConnection(IServerTransport transport, DnsReceivedRawPackage query, TaskCompletionSource<DnsRawPackage?> tcs)
		{
			Transport = transport;
			_query = query;
			_tcs = tcs;
		}

		public void Dispose()
		{
			_tcs.TrySetResult(null);
		}

		public IServerTransport Transport { get; }

		public IPEndPoint RemoteEndPoint => _query.RemoteEndpoint;

		public IPEndPoint LocalEndPoint => _query.LocalEndpoint;

		public bool CanRead { get; private set; } = true;

		public Task<bool> InitializeAsync(CancellationToken token = default)
		{
			return Task.FromResult(true);
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			if (CanRead)
			{
				CanRead = false;
				return Task.FromResult<DnsReceivedRawPackage?>(_query);
			}

			return Task.FromResult<DnsReceivedRawPackage?>(null);
		}

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			return Task.FromResult(_tcs.TrySetResult(package));
		}
	}
}