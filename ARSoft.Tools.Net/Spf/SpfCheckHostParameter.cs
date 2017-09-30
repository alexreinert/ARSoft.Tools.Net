using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

namespace ARSoft.Tools.Net.Spf
{
	internal class SpfCheckHostParameter
	{
		public SpfCheckHostParameter(IPAddress clientAddress, string clientName, string heloName, string domain, string sender)
		{
			LoopCount = 0;
			ClientAddress = clientAddress;
			ClientName = clientName;
			HeloName = heloName;
			CurrentDomain = domain;
			Sender = sender;
		}

		public SpfCheckHostParameter(string newDomain, SpfCheckHostParameter oldParameters)
		{
			LoopCount = oldParameters.LoopCount + 1;
			ClientAddress = oldParameters.ClientAddress;
			ClientName = oldParameters.ClientName;
			HeloName = oldParameters.HeloName;
			CurrentDomain = newDomain;
			Sender = oldParameters.Sender;
		}

		public int LoopCount;
		public IPAddress ClientAddress;
		public string ClientName;
		public string HeloName;
		public string CurrentDomain;
		public string Sender;
	}
}
