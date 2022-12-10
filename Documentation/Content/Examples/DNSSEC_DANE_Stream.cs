IDnsSecResolver resolver = new DnsSecRecursiveDnsResolver();
using (TcpClient client = new TcpClient("example.com", 443))
{
	using (DaneStream stream = new DaneStream(client.GetStream(), resolver))
	{
		stream.AuthenticateAsClient("example.com", 443);

		if (stream.IsAuthenticatedByDane)
			Console.WriteLine("Stream is authenticated by DANE/TLSA");

		// work with the stream
	}
}