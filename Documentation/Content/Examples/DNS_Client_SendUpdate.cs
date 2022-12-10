string key_name = "my-key";
string key_data = "0jnu3SdsMvzzlmTDPYRceA==";

DnsUpdateMessage msg = new DnsUpdateMessage
{
	ZoneName = DomainName.Parse("example.com")
};

msg.Updates.Add(new DeleteAllRecordsUpdate(DomainName.Parse("dyn.example.com"), RecordType.A));
msg.Updates.Add(new AddRecordUpdate(new ARecord(DomainName.Parse("dyn.example.com"), 60, IPAddress.Parse("192.0.2.42"))));
msg.TSigOptions = new TSigRecord(DomainName.Parse(key_name), TSigAlgorithm.Md5, DateTime.Now, new TimeSpan(0, 5, 0), msg.TransactionID, ReturnCode.NoError, null, Convert.FromBase64String(key_data));

DnsUpdateMessage dnsResult = new DnsClient(IPAddress.Parse("192.0.2.1"), 5000).SendUpdate(msg);
