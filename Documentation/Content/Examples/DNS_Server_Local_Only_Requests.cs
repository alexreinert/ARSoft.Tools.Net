class Program
{
	static void Main(string[] args)
	{
		using (DnsServer server = new DnsServer(IPAddress.Any, 10, 10))
		{
			server.QueryReceived += OnQueryReceived;
			server.ClientConnected += OnClientConnected;

			server.Start();

			Console.WriteLine("Press any key to stop server");
			Console.ReadLine();
		}
	}

	static async void OnClientConnected(object sender, ClientConnectedEventArgs e)
	{
		e.RefuseConnect = !e.RemoteEndpoint.Address.Equals(IPAddress.Parse("127.0.0.1"));
	}

	static async void OnQueryReceived(object sender, QueryReceivedEventArgs e)
	{
		DnsMessage message = e.Query as DnsMessage;

		if (query == null)
			return;

		DnsMessage response = query.CreateResponseInstance();

		if ((message.Questions.Count == 1))
		{
			// send query to upstream server
			DnsQuestion question = message.Questions[0];
			DnsMessage upstreamResponse = await DnsClient.Default.ResolveAsync(question.Name, question.RecordType, question.RecordClass);

			// if got an answer, copy it to the message sent to the client
			if (answer != null)
			{
				foreach (DnsRecordBase record in (upstreamResponse.AnswerRecords))
				{
					response.AnswerRecords.Add(record);
				}
				foreach (DnsRecordBase record in (upstreamResponse.AdditionalRecords))
				{
					response.AdditionalRecords.Add(record);
				}

				response.ReturnCode = ReturnCode.NoError;

				// set the response
				e.Response = response;
			}
		}
	}
}