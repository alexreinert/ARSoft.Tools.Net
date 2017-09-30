#region Copyright and License
// Copyright 2010..2015 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Dns
{
	public class Zone : ICollection<DnsRecordBase>
	{
		private static Regex _commentRemoverRegex = new Regex(@"^(?<data>([^\""]+?|(\""[^\""]*?\""))*?)(;.*)?$", RegexOptions.Compiled);
		private static Regex _lineSplitterRegex = new Regex("([^\\s\"]+)|\"(.*?(?<!\\\\))\"", RegexOptions.Compiled);

		private readonly List<DnsRecordBase> _records;

		public Zone()
		{
			_records = new List<DnsRecordBase>();
		}

		public Zone(IEnumerable<DnsRecordBase> collection)
		{
			_records = new List<DnsRecordBase>(collection);
		}

		public Zone(int capacity)
		{
			_records = new List<DnsRecordBase>(capacity);
		}

		public static Zone ParseMasterFile(string zoneFile, string origin = ".")
		{
			using (StreamReader reader = new StreamReader(zoneFile))
			{
				return ParseMasterFile(reader, origin);
			}
		}

		public static Zone ParseMasterFile(Stream zoneFile, string origin = ".")
		{
			using (StreamReader reader = new StreamReader(zoneFile))
			{
				return ParseMasterFile(reader, origin);
			}
		}

		private static Zone ParseMasterFile(StreamReader reader, string origin)
		{
			List<DnsRecordBase> records = ParseRecords(reader, origin, 0, new UnknownRecord(origin, RecordType.Invalid, RecordClass.Invalid, 0, new byte[] { }));

			SoaRecord soa = (SoaRecord) records.Single(x => x.RecordType == RecordType.Soa);

			records.ForEach(x =>
			{
				if (x.TimeToLive == 0)
					x.TimeToLive = soa.NegativeCachingTTL;
			});

			return new Zone(records);
		}

		private static List<DnsRecordBase> ParseRecords(StreamReader reader, string origin, int ttl, DnsRecordBase lastRecord)
		{
			List<DnsRecordBase> records = new List<DnsRecordBase>();

			while (!reader.EndOfStream)
			{
				string line = ReadRecordLine(reader);

				if (!String.IsNullOrEmpty(line))
				{
					string[] parts = _lineSplitterRegex.Matches(line).Cast<Match>().Select(x => x.Groups.Cast<Group>().Last(g => g.Success).Value.Replace("\\\"", "\"")).ToArray();

					if (parts[0].Equals("$origin", StringComparison.InvariantCultureIgnoreCase))
					{
						origin = parts[1];
					}
					if (parts[0].Equals("$ttl", StringComparison.InvariantCultureIgnoreCase))
					{
						ttl = Int32.Parse(parts[1]);
					}
					if (parts[0].Equals("$include", StringComparison.InvariantCultureIgnoreCase))
					{
						FileStream fileStream = reader.BaseStream as FileStream;

						if (fileStream == null)
							throw new NotSupportedException("Includes only supported when loading files");

						string path = Path.Combine(new FileInfo(fileStream.Name).DirectoryName, parts[1]);

						string includeOrigin = (parts.Length > 2) ? parts[2] : origin;

						using (StreamReader includeReader = new StreamReader(path))
						{
							records.AddRange(ParseRecords(includeReader, includeOrigin, ttl, lastRecord));
						}
					}
					else
					{
						string domain;
						RecordType recordType;
						RecordClass recordClass;
						int recordTtl;
						string[] rrData;

						if (Int32.TryParse(parts[0], out recordTtl))
						{
							// no domain, starts with ttl
							if (RecordClassHelper.TryParseShortString(parts[1], out recordClass))
							{
								// second is record class
								domain = null;
								recordType = RecordTypeHelper.ParseShortString(parts[2]);
								rrData = parts.Skip(3).ToArray();
							}
							else
							{
								// no record class
								domain = null;
								recordClass = RecordClass.Invalid;
								recordType = RecordTypeHelper.ParseShortString(parts[1]);
								rrData = parts.Skip(2).ToArray();
							}
						}
						else if (RecordClassHelper.TryParseShortString(parts[0], out recordClass))
						{
							// no domain, starts with record class
							if (Int32.TryParse(parts[1], out recordTtl))
							{
								// second is ttl
								domain = null;
								recordType = RecordTypeHelper.ParseShortString(parts[2]);
								rrData = parts.Skip(3).ToArray();
							}
							else
							{
								// no ttl
								recordTtl = 0;
								domain = null;
								recordType = RecordTypeHelper.ParseShortString(parts[1]);
								rrData = parts.Skip(2).ToArray();
							}
						}
						else if (RecordTypeHelper.TryParseShortString(parts[0], out recordType))
						{
							// no domain, start with record type
							recordTtl = 0;
							recordClass = RecordClass.Invalid;
							domain = null;
							rrData = parts.Skip(2).ToArray();
						}
						else
						{
							domain = parts[0];

							if (Int32.TryParse(parts[1], out recordTtl))
							{
								// domain, second is ttl
								if (RecordClassHelper.TryParseShortString(parts[2], out recordClass))
								{
									// third is record class
									recordType = RecordTypeHelper.ParseShortString(parts[3]);
									rrData = parts.Skip(4).ToArray();
								}
								else
								{
									// no record class
									recordClass = RecordClass.Invalid;
									recordType = RecordTypeHelper.ParseShortString(parts[2]);
									rrData = parts.Skip(3).ToArray();
								}
							}
							else if (RecordClassHelper.TryParseShortString(parts[1], out recordClass))
							{
								// domain, second is record class
								if (Int32.TryParse(parts[2], out recordTtl))
								{
									// third is ttl
									recordType = RecordTypeHelper.ParseShortString(parts[3]);
									rrData = parts.Skip(4).ToArray();
								}
								else
								{
									// no ttl
									recordTtl = 0;
									recordType = RecordTypeHelper.ParseShortString(parts[2]);
									rrData = parts.Skip(3).ToArray();
								}
							}
							else
							{
								// domain with record type
								recordType = RecordTypeHelper.ParseShortString(parts[1]);
								recordTtl = 0;
								recordClass = RecordClass.Invalid;
								rrData = parts.Skip(2).ToArray();
							}
						}

						if (String.IsNullOrEmpty(domain))
						{
							domain = lastRecord.Name;
						}
						else if (domain == "@")
						{
							domain = origin;
						}
						else if (!domain.EndsWith("."))
						{
							domain = domain + "." + origin;
						}

						if (recordClass == RecordClass.Invalid)
						{
							recordClass = lastRecord.RecordClass;
						}

						if (recordType == RecordType.Invalid)
						{
							recordType = lastRecord.RecordType;
						}

						if (recordTtl == 0)
						{
							recordTtl = ttl;
						}
						else
						{
							ttl = recordTtl;
						}

						lastRecord = DnsRecordBase.Create(recordType);
						lastRecord.RecordType = recordType;
						lastRecord.Name = domain.TrimEnd('.');
						lastRecord.RecordClass = recordClass;
						lastRecord.TimeToLive = recordTtl;

						if ((rrData.Length > 0) && (rrData[0].StartsWith(@"\#")))
						{
							lastRecord.ParseUnknownRecordData(rrData);
						}
						else
						{
							lastRecord.ParseRecordData(origin, rrData);
						}

						records.Add(lastRecord);
					}
				}
			}

			return records;
		}

		private static string ReadRecordLine(StreamReader reader)
		{
			string line = ReadLineWithoutComment(reader);

			int bracketPos;
			if ((bracketPos = line.IndexOf('(')) != -1)
			{
				StringBuilder sb = new StringBuilder();

				sb.Append(line.Substring(0, bracketPos));
				sb.Append(" ");
				sb.Append(line.Substring(bracketPos + 1));

				while (true)
				{
					sb.Append(" ");

					line = ReadLineWithoutComment(reader);

					if ((bracketPos = line.IndexOf(')')) == -1)
					{
						sb.Append(line);
					}
					else
					{
						sb.Append(line.Substring(0, bracketPos));
						sb.Append(" ");
						sb.Append(line.Substring(bracketPos + 1));
						line = sb.ToString();
						break;
					}
				}
			}

			return line;
		}

		private static string ReadLineWithoutComment(StreamReader reader)
		{
			string line = reader.ReadLine();
			return _commentRemoverRegex.Match(line).Groups["data"].Value;
		}

		public void Add(DnsRecordBase item)
		{
			_records.Add(item);
		}

		public void Clear()
		{
			_records.Clear();
		}

		public bool Contains(DnsRecordBase item)
		{
			return _records.Contains(item);
		}

		public void CopyTo(DnsRecordBase[] array, int arrayIndex)
		{
			_records.CopyTo(array, arrayIndex);
		}

		public int Count
		{
			get { return _records.Count; }
		}

		bool ICollection<DnsRecordBase>.IsReadOnly
		{
			get { return false; }
		}

		public bool Remove(DnsRecordBase item)
		{
			return _records.Remove(item);
		}

		public IEnumerator<DnsRecordBase> GetEnumerator()
		{
			return _records.GetEnumerator();
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}
	}
}