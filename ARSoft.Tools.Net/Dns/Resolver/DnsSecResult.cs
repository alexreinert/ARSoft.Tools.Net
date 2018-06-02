﻿#region Copyright and License

// Copyright 2010..2017 Alexander Reinert
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

using System.Collections.Generic;
using ARSoft.Tools.Net.Dns.DnsRecord;

namespace ARSoft.Tools.Net.Dns.Resolver
{
    /// <summary>
    ///     The response of a secure DNS resolver
    /// </summary>
    public class DnsSecResult<T>
        where T : DnsRecordBase
    {
        internal DnsSecResult(List<T> records, DnsSecValidationResult validationResult)
        {
            Records = records;
            ValidationResult = validationResult;
        }

        /// <summary>
        ///     The result of the validation process
        /// </summary>
        public DnsSecValidationResult ValidationResult { get; }

        /// <summary>
        ///     The records representing the response
        /// </summary>
        public List<T> Records { get; }
    }
}