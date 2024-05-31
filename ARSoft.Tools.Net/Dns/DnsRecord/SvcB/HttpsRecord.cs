#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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
///   <para>HTTPS Service Binding</para>
///   <para>
///     Defined in
///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
///   </para>
/// </summary>
public class HttpsRecord : SvcBRecord
{
	internal HttpsRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
		: base(name, recordType, recordClass, timeToLive, resultData, currentPosition, length) { }

	internal HttpsRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
		: base(name, recordType, recordClass, timeToLive, origin, stringRepresentation) { }

	/// <summary>
	///   Creates a new instance of the HttpsRecord class
	/// </summary>
	/// <param name="name"> Name of the record </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="priority"> Priority of the record </param>
	/// <param name="target"> Domain name of the target host </param>
	/// <param name="parameters"> A key-value-list of Service Binding parameters</param>
	public HttpsRecord(DomainName name, int timeToLive, ushort priority, DomainName target, Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>? parameters = null)
		: base(name, RecordType.Https, timeToLive, priority, target, parameters) { }
}