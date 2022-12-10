IDnsResolver resolver = new DnsStubResolver();
List<IPAddress> addresses = resolver.ResolveHost("www.example.com");
