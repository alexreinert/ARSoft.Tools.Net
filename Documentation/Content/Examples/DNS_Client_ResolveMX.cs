DnsMessage dnsMessage = DnsClient.Default.Resolve(DomainName.Parse("example.com"), RecordType.Mx);
if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
{
	throw new Exception("DNS request failed");
}
else
{
	foreach (DnsRecordBase dnsRecord in dnsMessage.AnswerRecords)
	{
		MxRecord mxRecord = dnsRecord as MxRecord;
		if (mxRecord != null)
		{
			Console.WriteLine(mxRecord.ExchangeDomainName);
		}
	}
}