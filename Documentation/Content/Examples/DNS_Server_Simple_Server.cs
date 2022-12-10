class Program
{
	static void Main(string[] args)
	{
		using (DnsServer server = new DnsServer(10, 10))
		{
			server.QueryReceived += OnQueryReceived;

			server.Start();

			Console.WriteLine("Press any key to stop server");
			Console.ReadLine();
		}
	}

	static async Task OnQueryReceived(object sender, QueryReceivedEventArgs e)
	{
		DnsMessage query = e.Query as DnsMessage;

		if (query == null)
			return;

		DnsMessage response = query.CreateResponseInstance();

		// check for valid query
		if ((query.Questions.Count == 1)
		    && (query.Questions[0].RecordType == RecordType.Txt)
		    && (query.Questions[0].Name.Equals(DomainName.Parse("example.com"))))
		{
			response.ReturnCode = ReturnCode.NoError;
			response.AnswerRecords.Add(new TxtRecord(DomainName.Parse("example.com"), 3600, "Hello world"));
		}
		else
		{
			response.ReturnCode = ReturnCode.ServerFailure;
		}

		// set the response
		e.Response = response;
	}
}