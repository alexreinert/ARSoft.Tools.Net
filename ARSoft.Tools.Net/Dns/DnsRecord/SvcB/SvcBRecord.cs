#region Copyright and License
// Copyright 2010..2023 Alexander Reinert
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

/// <summary>
///   <para>Service Binding</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
public class SvcBRecord : DnsRecordBase
{
	/// <summary>
	///   Priority of the record
	/// </summary>
	public ushort Priority { get; private set; }

	/// <summary>
	///   Target of the record
	/// </summary>
	public DomainName Target { get; private set; }

	/// <summary>
	///   A key-value-list of Service Binding parameters
	/// </summary>
	public Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase> Parameters { get; private set; }

	internal SvcBRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
		: base(name, recordType, recordClass, timeToLive)
	{
		int endPosition = currentPosition + length;

		Priority = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
		Target = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);

		Parameters = new Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>();
		while (currentPosition < endPosition)
		{
			var parameter = ServiceBindingParameterBase.ParseServiceBindingParameter(resultData, ref currentPosition);
			Parameters.Add(parameter.Key, parameter);
		}
	}

	internal SvcBRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
		: base(name, recordType, recordClass, timeToLive)
	{
		if (stringRepresentation.Length < 2)
			throw new FormatException();

		Priority = UInt16.Parse(stringRepresentation[0]);
		Target = ParseDomainName(origin, stringRepresentation[1]);

		Parameters = new Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>();
		for (var i = 2; i < stringRepresentation.Length; i++)
		{
			var s = stringRepresentation[i];

			var parts = s.Split('=', 2);

			var type = ServiceBindingParameterKeyHelper.Parse(parts[0]);

			if (parts.Length == 1)
			{
				Parameters.Add(type, ServiceBindingParameterBase.ParseServiceBindingParameter(type, null));
			}
			else if (String.IsNullOrEmpty(parts[1]))
			{
				if (i + 1 >= stringRepresentation.Length)
				{
					throw new FormatException();
				}

				i++;
				Parameters.Add(type, ServiceBindingParameterBase.ParseServiceBindingParameter(type, stringRepresentation[i]));
			}
			else
			{
				Parameters.Add(type, ServiceBindingParameterBase.ParseServiceBindingParameter(type, parts[1]));
			}
		}
	}

	/// <summary>
	///   Creates a new instance of the SrvRecord class
	/// </summary>
	/// <param name="name"> Name of the record </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="priority"> Priority of the record </param>
	/// <param name="target"> Domain name of the target host </param>
	/// <param name="parameters"> A key-value-list of Service Binding parameters</param>
	public SvcBRecord(DomainName name, int timeToLive, ushort priority, DomainName target, Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>? parameters = null)
		: this(name, RecordType.SvcB, timeToLive, priority, target, parameters) { }

	protected SvcBRecord(DomainName name, RecordType recordType, int timeToLive, ushort priority, DomainName target, Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>? parameters = null)
		: base(name, recordType, RecordClass.INet, timeToLive)
	{
		Priority = priority;
		Target = target;
		Parameters = parameters ?? new Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>();
	}

	internal override string RecordDataToString()
	{
		return Priority
		       + " " + Target.ToString(true)
		       + String.Join(String.Empty, Parameters.Values.Select(p => " " + p));
	}

	protected internal override int MaximumRecordDataLength => 4 + Target.MaximumRecordDataLength + Parameters.Sum(p => p.Value.MaximumRecordDataLength);

	protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
	{
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Priority);
		DnsMessageBase.EncodeDomainName(messageData, ref currentPosition, Target, null, useCanonical);
		foreach (var parameter in Parameters.OrderBy(x => x.Key))
		{
			parameter.Value.EncodeParameterData(messageData, ref currentPosition, useCanonical);
		}
	}
}