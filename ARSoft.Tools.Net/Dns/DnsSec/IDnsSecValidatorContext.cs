namespace ARSoft.Tools.Net.Dns.DnsSec
{
	internal interface IDnsSecValidatorContext
	{
		bool HasDomainAlreadyBeenResolvedInValidation(DomainName name, RecordType recordType);
		void AddResolvedDomainInValidation(DomainName name, RecordType recordType);
	}
}
