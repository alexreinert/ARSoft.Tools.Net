DnsMessage dnsMessage = DnsClient.Default.Resolve(IPAddress.Parse("192.0.2.1").GetReverseLookupDomain(), RecordType.Ptr);
if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
{
	throw new Exception("DNS request failed");
}
else
{
	foreach (DnsRecordBase dnsRecord in dnsMessage.AnswerRecords)
	{
		PtrRecord ptrRecord = dnsRecord as PtrRecord;
		if (ptrRecord != null)
		{
			Console.WriteLine(ptrRecord.PointerDomainName);
		}
	}
}