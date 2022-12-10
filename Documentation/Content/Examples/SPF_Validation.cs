var validator = new SpfValidator()
{
	HeloDomain = DomainName.Parse("example.com"),
	LocalDomain = DomainName.Parse("receivingmta.example.com"),
	LocalIP = IPAddress.Parse("192.0.2.1")
};

SpfQualifier result = validator.CheckHost(IPAddress.Parse("192.0.2.200"), DomainName.Parse("example.com"), "sender@example.com").Result;