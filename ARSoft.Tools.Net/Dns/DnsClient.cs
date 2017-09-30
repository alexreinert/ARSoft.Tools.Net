using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.IO;

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

			DnsMessage message = new DnsMessage() { TransactionID = (ushort)new Random().Next(0xffff), IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true };
			message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

			return SendMessage(message);
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

			using (UdpClient udpClient = new UdpClient())
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

			using (TcpClient tcpClient = new TcpClient())
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
