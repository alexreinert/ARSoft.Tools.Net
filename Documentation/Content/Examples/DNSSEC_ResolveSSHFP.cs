IDnsSecResolver resolver = new SelfValidatingInternalDnsSecStubResolver();
DnsSecResult<SshFpRecord> result = resolver.ResolveSecure<SshFpRecord>("example.com", RecordType.SshFp);
if (result.ValidationResult == DnsSecValidationResult.Signed)
{
	Console.WriteLine("example.com has following signed SSH fingerprint records:");
	result.Records.ForEach(x => Console.WriteLine(x.ToString()));
}
else
{
	Console.WriteLine("example.com has no signed SSH fingerprint records");
}