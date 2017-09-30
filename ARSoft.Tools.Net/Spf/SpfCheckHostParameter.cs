#region Copyright and License
// Copyright 2010 Alexander Reinert
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

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