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
///   The type of a <see cref="ServiceBindingParameterBase" />.
/// </summary>
public enum ServiceBindingParameterKey : ushort
{
	/// <summary>
	///   <para>Mandatory keys</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	Mandatory = 0,

	/// <summary>
	///   <para>Additional supported protocols</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	// ReSharper disable once IdentifierTypo
	ALPN = 1,

	/// <summary>
	///   <para>No support for default protocol</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	// ReSharper disable once IdentifierTypo
	NoDefaultALPN = 2,

	/// <summary>
	///   <para>Port for alternative endpoint</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	Port = 3,

	/// <summary>
	///   <para>IPv4 address hints</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	IPv4Hint = 4,

	/// <summary>
	///   <para>RESERVED (will be used for ECH)</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once UnusedMember.Global
	// ReSharper disable once InconsistentNaming
	ECH = 5,

	/// <summary>
	///   <para>IPv6 address hints</para>
	///   <para>
	///     Defined in
	///     <a href="https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/12/">draft-ietf-dnsop-svcb-https</a>.
	///   </para>
	/// </summary>
	// ReSharper disable once InconsistentNaming
	IPv6Hint = 6
}