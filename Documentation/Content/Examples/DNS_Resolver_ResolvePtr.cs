IDnsResolver resolver = new DnsStubResolver();
DomainName name = resolver.ResolvePtr(IPAddress.Parse("192.0.2.1"));
