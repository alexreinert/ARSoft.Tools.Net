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

using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;

namespace ARSoft.Tools.Net.Dns;

public class HttpsClientTransport : IClientTransport
{
	private readonly HttpClient _client;
	private readonly Uri _uri;

	public HttpsClientTransport(Uri uri)
	{
		_uri = uri;

		_client = new HttpClient()
		{
			DefaultRequestVersion = HttpVersion.Version20,
			DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher,
		};

		_client.DefaultRequestHeaders.Accept.Clear();
		_client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
	}

	public void Dispose()
	{
		_client.TryDispose();
	}

	public ushort MaximumAllowedQuerySize => 512;

	public bool SupportsReliableTransfer => true;

	public bool SupportsMulticastTransfer => false;

	public bool SupportsPooledConnections => false;

	public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
	{
		return Task.FromResult<IClientConnection?>(new HttpsClientConnection(this, _client, _uri));
	}

	/// <summary>
	///   Gets connection from the pool
	/// </summary>
	/// <param name="endpointInfo">The endpoint of the connection</param>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
	Task<IClientConnection?> IClientTransport.GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token)
	{
		throw new NotSupportedException();
	}

	private class HttpsClientConnection : IClientConnection
	{
		private readonly HttpClient _client;
		private readonly Uri _uri;
		private DnsReceivedRawPackage? _receivedRawPackage;

		public IClientTransport Transport { get; }
		public bool IsFaulty { get; private set; } = true;

		public HttpsClientConnection(IClientTransport transport, HttpClient client, Uri uri)
		{
			Transport = transport;
			_client = client;
			_uri = uri;
		}

		public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			var content = new ByteArrayContent(package.ToArraySegment(false).ToArray());
			content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

			var response = await _client.PostAsync(_uri, content, token);

			if (!response.IsSuccessStatusCode)
				return false;

			using var ms = new MemoryStream();
			ms.WriteByte(0);
			ms.WriteByte(0);

			await response.Content.CopyToAsync(ms, token);

			var buffer = ms.ToArray();
			DnsMessageBase.EncodeUShort(buffer, 0, (ushort) (buffer.Length - 2));

			_receivedRawPackage = new DnsReceivedRawPackage(buffer, new IPEndPoint(IPAddress.None, 0), new IPEndPoint(IPAddress.None, 0));
			return true;
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
		{
			try
			{
				return Task.FromResult(_receivedRawPackage);
			}
			finally
			{
				_receivedRawPackage = null;
				MarkFaulty();
			}
		}

		void IClientConnection.RestartIdleTimeout(TimeSpan? timeout) { }

		public void MarkFaulty()
		{
			IsFaulty = true;
		}

		void IDisposable.Dispose() { }
	}
}