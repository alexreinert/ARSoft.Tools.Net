using System.Collections.Generic;

namespace ARSoft.Tools.Net.Dns.DnsSec
{
	internal class DnsSecValidatorContext : IDnsSecValidatorContext
	{
		private readonly HashSet<(DomainName Name, RecordType Type)> _ResolvedDomainNames = new HashSet<(DomainName, RecordType)>();
		
		public bool HasDomainAlreadyBeenResolvedInValidation(DomainName name, RecordType recordType) => _ResolvedDomainNames.Contains((name, recordType));
		public void AddResolvedDomainInValidation(DomainName name, RecordType recordType) => _ResolvedDomainNames.Add((name, recordType));
	}
}
