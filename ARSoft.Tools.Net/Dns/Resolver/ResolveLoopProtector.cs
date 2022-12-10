#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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

namespace ARSoft.Tools.Net.Dns;

internal class ResolveLoopProtector
{
	private readonly HashSet<DnsQuestion> _chain = new();

	public IDisposable AddOrThrow(DomainName name, RecordType recordType, RecordClass recordClass)
	{
		var question = new DnsQuestion(name, recordType, recordClass);

		if (_chain.Contains(question))
			throw new Exception("DNS Resolve loop detected");

		return new Disposable(_chain, question);
	}

	private class Disposable : IDisposable
	{
		private readonly HashSet<DnsQuestion> _chain;
		private readonly DnsQuestion _question;

		public Disposable(HashSet<DnsQuestion> chain, DnsQuestion question)
		{
			_chain = chain;
			_question = question;

			_chain.Add(question);
		}

		public void Dispose()
		{
			_chain.Remove(_question);
		}
	}
}