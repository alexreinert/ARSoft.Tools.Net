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

using System.IO;

namespace ARSoft.Tools.Net.Dns.Resolver
{
    /// <summary>
    ///   Updateable Resolver HintStore using a local zone file for the hints
    /// </summary>
    public class ZoneFileResolverHintStore : UpdateableResolverHintStoreBase
	{
		private readonly string _fileName;

		/// <summary>
		///   Creates a new instance of the ZoneFileResolverHintStore class
		/// </summary>
		/// <param name="fileName">The path to the local zone file containing the hints</param>
		public ZoneFileResolverHintStore(string fileName) => _fileName = fileName;

	    /// <summary>
		///   Saves the hints to the local file
		/// </summary>
		/// <param name="zone">The zone to save</param>
		protected override void Save(Zone zone)
		{
			using (var writer = new StreamWriter(_fileName))
			{
				foreach (var record in zone) writer.WriteLine(record.ToString());
			}
		}

		/// <summary>
		///   Loads the hints from the local file
		/// </summary>
		/// <returns></returns>
		protected override Zone Load()
		{
			if (!File.Exists(_fileName))
				throw new FileNotFoundException();

			return Zone.ParseMasterFile(DomainName.Root, _fileName);
		}
	}
}