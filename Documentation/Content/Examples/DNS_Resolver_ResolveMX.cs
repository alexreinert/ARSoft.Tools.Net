IDnsResolver resolver = new RecursiveDnsResolver();
List<MxRecord> mxRecords = resolver.Resolve<MxRecord>("example.com", RecordType.Mx);
