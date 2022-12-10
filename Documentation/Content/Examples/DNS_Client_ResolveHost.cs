DnsMessage dnsMessage = DnsClient.Default.Resolve(DomainName.Parse(www.example.com), RecordType.A);
if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
{
	throw new Exception("DNS request failed");
}
else
{
	foreach (DnsRecordBase dnsRecord in dnsMessage.AnswerRecords)
	{
		ARecord aRecord = dnsRecord as ARecord;
		if (aRecord != null)
		{
			Console.WriteLine(aRecord.Address.ToString());
		}
	}
}