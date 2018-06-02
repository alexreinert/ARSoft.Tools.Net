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


namespace ARSoft.Tools.Net.Dns.EDns
{
    /// <summary>
    ///     Base class of EDNS options
    /// </summary>
    public abstract class EDnsOptionBase
    {
        internal EDnsOptionBase(EDnsOptionType optionType) => Type = optionType;

        /// <summary>
        ///     Type of the option
        /// </summary>
        public EDnsOptionType Type { get; internal set; }

        internal abstract ushort DataLength { get; }

        internal abstract void ParseData(byte[] resultData, int startPosition, int length);
        internal abstract void EncodeData(byte[] messageData, ref int currentPosition);
    }
}