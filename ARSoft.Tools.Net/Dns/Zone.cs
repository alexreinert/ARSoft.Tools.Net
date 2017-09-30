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
using Org.BouncyCastle.Security;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Class representing a DNS zone
	/// </summary>
	public class Zone : ICollection<DnsRecordBase>
	{
		private static readonly Regex _commentRemoverRegex = new Regex(@"^(?<data>(\\\""|[^\""]|(?<!\\)\"".*?(?<!\\)\"")*?)(;.*)?$", RegexOptions.Compiled | RegexOptions.ExplicitCapture);
		private static readonly Regex _lineSplitterRegex = new Regex("([^\\s\"]+)|\"(.*?(?<!\\\\))\"", RegexOptions.Compiled);

		private readonly List<DnsRecordBase> _records;

		/// <summary>
		///   Gets the name of the Zone
		/// </summary>
		public DomainName Name { get; }

		/// <summary>
		///   Creates a new instance of the Zone class with no records
		/// </summary>
		/// <param name="name">The name of the zone</param>
		public Zone(DomainName name)
		{
			Name = name;
			_records = new List<DnsRecordBase>();
		}

		/// <summary>
		///   Creates a new instance of the Zone class that contains records copied from the specified collection
		/// </summary>
		/// <param name="name">The name of the zone</param>
		/// <param name="collection">Collection of records which are copied to the new Zone instance</param>
		public Zone(DomainName name, IEnumerable<DnsRecordBase> collection)
		{
			Name = name;
			_records = new List<DnsRecordBase>(collection);
		}

		/// <summary>
		///   Create a new instance of the Zone class with the specified initial capacity
		/// </summary>
		/// <param name="name">The name of the zone</param>
		/// <param name="capacity">The initial capacity for the new Zone instance</param>
		public Zone(DomainName name, int capacity)
		{
			Name = name;
			_records = new List<DnsRecordBase>(capacity);
		}

		/// <summary>
		///   Loads a Zone from a master file
		/// </summary>
		/// <param name="name">The name of the zone</param>
		/// <param name="zoneFile">Path to the Zone master file</param>
		/// <returns>A new instance of the Zone class</returns>
		public static Zone ParseMasterFile(DomainName name, string zoneFile)
		{
			using (StreamReader reader = new StreamReader(zoneFile))
			{
				return ParseMasterFile(name, reader);
			}
		}

		/// <summary>
		///   Loads a Zone from a master data stream
		/// </summary>
		/// <param name="name">The name of the zone</param>
		/// <param name="zoneFile">Stream containing the zone master data</param>
		/// <returns>A new instance of the Zone class</returns>
		public static Zone ParseMasterFile(DomainName name, Stream zoneFile)
		{
			using (StreamReader reader = new StreamReader(zoneFile))
			{
				return ParseMasterFile(name, reader);
			}
		}

		private static Zone ParseMasterFile(DomainName name, StreamReader reader)
		{
			List<DnsRecordBase> records = ParseRecords(reader, name, 0, new UnknownRecord(name, RecordType.Invalid, RecordClass.INet, 0, new byte[] { }));

			SoaRecord soa = (SoaRecord) records.SingleOrDefault(x => x.RecordType == RecordType.Soa);

			if (soa != null)
			{
				records.ForEach(x =>
				{
					if (x.TimeToLive == 0)
						x.TimeToLive = soa.NegativeCachingTTL;
				});
			}

			return new Zone(name, records);
		}

		private static List<DnsRecordBase> ParseRecords(StreamReader reader, DomainName origin, int ttl, DnsRecordBase lastRecord)
		{
			List<DnsRecordBase> records = new List<DnsRecordBase>();

			while (!reader.EndOfStream)
			{
				string line = ReadRecordLine(reader);

				if (!String.IsNullOrEmpty(line))
				{
					string[] parts = _lineSplitterRegex.Matches(line).Cast<Match>().Select(x => x.Groups.Cast<Group>().Last(g => g.Success).Value.FromMasterfileLabelRepresentation()).ToArray();

					if (parts[0].Equals("$origin", StringComparison.InvariantCultureIgnoreCase))
					{
						origin = DomainName.ParseFromMasterfile(parts[1]);
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

						// ReSharper disable once AssignNullToNotNullAttribute
						string path = Path.Combine(new FileInfo(fileStream.Name).DirectoryName, parts[1]);

						DomainName includeOrigin = (parts.Length > 2) ? DomainName.ParseFromMasterfile(parts[2]) : origin;

						using (StreamReader includeReader = new StreamReader(path))
						{
							records.AddRange(ParseRecords(includeReader, includeOrigin, ttl, lastRecord));
						}
					}
					else
					{
						string domainString;
						RecordType recordType;
						RecordClass recordClass;
						int recordTtl;
						string[] rrData;

						if (Int32.TryParse(parts[0], out recordTtl))
						{
							// no domain, starts with ttl
							if (RecordClassHelper.TryParseShortString(parts[1], out recordClass, false))
							{
								// second is record class
								domainString = null;
								recordType = RecordTypeHelper.ParseShortString(parts[2]);
								rrData = parts.Skip(3).ToArray();
							}
							else
							{
								// no record class
								domainString = null;
								recordClass = RecordClass.Invalid;
								recordType = RecordTypeHelper.ParseShortString(parts[1]);
								rrData = parts.Skip(2).ToArray();
							}
						}
						else if (RecordClassHelper.TryParseShortString(parts[0], out recordClass, false))
						{
							// no domain, starts with record class
							if (Int32.TryParse(parts[1], out recordTtl))
							{
								// second is ttl
								domainString = null;
								recordType = RecordTypeHelper.ParseShortString(parts[2]);
								rrData = parts.Skip(3).ToArray();
							}
							else
							{
								// no ttl
								recordTtl = 0;
								domainString = null;
								recordType = RecordTypeHelper.ParseShortString(parts[1]);
								rrData = parts.Skip(2).ToArray();
							}
						}
						else if (RecordTypeHelper.TryParseShortString(parts[0], out recordType))
						{
							// no domain, start with record type
							recordTtl = 0;
							recordClass = RecordClass.Invalid;
							domainString = null;
							rrData = parts.Skip(2).ToArray();
						}
						else
						{
							domainString = parts[0];

							if (Int32.TryParse(parts[1], out recordTtl))
							{
								// domain, second is ttl
								if (RecordClassHelper.TryParseShortString(parts[2], out recordClass, false))
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
							else if (RecordClassHelper.TryParseShortString(parts[1], out recordClass, false))
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

						DomainName domain;
						if (String.IsNullOrEmpty(domainString))
						{
							domain = lastRecord.Name;
						}
						else if (domainString == "@")
						{
							domain = origin;
						}
						else if (domainString.EndsWith("."))
						{
							domain = DomainName.ParseFromMasterfile(domainString);
						}
						else
						{
							domain = DomainName.ParseFromMasterfile(domainString) + origin;
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
						lastRecord.Name = domain;
						lastRecord.RecordClass = recordClass;
						lastRecord.TimeToLive = recordTtl;

						if ((rrData.Length > 0) && (rrData[0] == @"\#"))
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
			// ReSharper disable once AssignNullToNotNullAttribute
			return _commentRemoverRegex.Match(line).Groups["data"].Value;
		}

		/// <summary>
		///   Signs a zone
		/// </summary>
		/// <param name="keys">A list of keys to sign the zone</param>
		/// <param name="inception">The inception date of the signatures</param>
		/// <param name="expiration">The expiration date of the signatures</param>
		/// <param name="nsec3Algorithm">The NSEC3 algorithm (or 0 when NSEC should be used)</param>
		/// <param name="nsec3Iterations">The number of iterations when NSEC3 is used</param>
		/// <param name="nsec3Salt">The salt when NSEC3 is used</param>
		/// <param name="nsec3OptOut">true, of NSEC3 OptOut should be used for delegations without DS record</param>
		/// <returns>A signed zone</returns>
		public Zone Sign(List<DnsKeyRecord> keys, DateTime inception, DateTime expiration, NSec3HashAlgorithm nsec3Algorithm = 0, int nsec3Iterations = 10, byte[] nsec3Salt = null, bool nsec3OptOut = false)
		{
			if ((keys == null) || (keys.Count == 0))
				throw new Exception("No DNS Keys were provided");

			if (!keys.All(x => x.IsZoneKey))
				throw new Exception("No DNS key with Zone Key Flag were provided");

			if (keys.Any(x => (x.PrivateKey == null) || (x.PrivateKey.Length == 0)))
				throw new Exception("For at least one DNS key no Private Key was provided");

			if (keys.Any(x => (x.Protocol != 3) || ((nsec3Algorithm != 0) ? !x.Algorithm.IsCompatibleWithNSec3() : !x.Algorithm.IsCompatibleWithNSec())))
				throw new Exception("At least one invalid DNS key was provided");

			List<DnsKeyRecord> keySigningKeys = keys.Where(x => x.IsSecureEntryPoint).ToList();
			List<DnsKeyRecord> zoneSigningKeys = keys.Where(x => !x.IsSecureEntryPoint).ToList();

			if (nsec3Algorithm == 0)
			{
				return SignWithNSec(inception, expiration, zoneSigningKeys, keySigningKeys);
			}
			else
			{
				return SignWithNSec3(inception, expiration, zoneSigningKeys, keySigningKeys, nsec3Algorithm, nsec3Iterations, nsec3Salt, nsec3OptOut);
			}
		}

		private Zone SignWithNSec(DateTime inception, DateTime expiration, List<DnsKeyRecord> zoneSigningKeys, List<DnsKeyRecord> keySigningKeys)
		{
			var soaRecord = _records.OfType<SoaRecord>().First();
			var subZones = _records.Where(x => (x.RecordType == RecordType.Ns) && (x.Name != Name)).Select(x => x.Name).Distinct().ToList();
			var glueRecords = _records.Where(x => subZones.Any(y => x.Name.IsSubDomainOf(y))).ToList();
			var recordsByName = _records.Except(glueRecords).Union(zoneSigningKeys).Union(keySigningKeys).GroupBy(x => x.Name).Select(x => new Tuple<DomainName, List<DnsRecordBase>>(x.Key, x.OrderBy(y => y.RecordType == RecordType.Soa ? -1 : (int) y.RecordType).ToList())).OrderBy(x => x.Item1).ToList();

			Zone res = new Zone(Name, Count * 3);

			for (int i = 0; i < recordsByName.Count; i++)
			{
				List<RecordType> recordTypes = new List<RecordType>();

				DomainName currentName = recordsByName[i].Item1;

				foreach (var recordsByType in recordsByName[i].Item2.GroupBy(x => x.RecordType))
				{
					List<DnsRecordBase> records = recordsByType.ToList();

					recordTypes.Add(recordsByType.Key);
					res.AddRange(records);

					// do not sign nameserver delegations for sub zones
					if ((records[0].RecordType == RecordType.Ns) && (currentName != Name))
						continue;

					recordTypes.Add(RecordType.RrSig);

					foreach (var key in zoneSigningKeys)
					{
						res.Add(new RrSigRecord(records, key, inception, expiration));
					}
					if (records[0].RecordType == RecordType.DnsKey)
					{
						foreach (var key in keySigningKeys)
						{
							res.Add(new RrSigRecord(records, key, inception, expiration));
						}
					}
				}

				recordTypes.Add(RecordType.NSec);

				NSecRecord nsecRecord = new NSecRecord(recordsByName[i].Item1, soaRecord.RecordClass, soaRecord.NegativeCachingTTL, recordsByName[(i + 1) % recordsByName.Count].Item1, recordTypes);
				res.Add(nsecRecord);

				foreach (var key in zoneSigningKeys)
				{
					res.Add(new RrSigRecord(new List<DnsRecordBase>() { nsecRecord }, key, inception, expiration));
				}
			}

			res.AddRange(glueRecords);

			return res;
		}

		private Zone SignWithNSec3(DateTime inception, DateTime expiration, List<DnsKeyRecord> zoneSigningKeys, List<DnsKeyRecord> keySigningKeys, NSec3HashAlgorithm nsec3Algorithm, int nsec3Iterations, byte[] nsec3Salt, bool nsec3OptOut)
		{
			var soaRecord = _records.OfType<SoaRecord>().First();
			var subZoneNameserver = _records.Where(x => (x.RecordType == RecordType.Ns) && (x.Name != Name)).ToList();
			var subZones = subZoneNameserver.Select(x => x.Name).Distinct().ToList();
			var unsignedRecords = _records.Where(x => subZones.Any(y => x.Name.IsSubDomainOf(y))).ToList(); // glue records
			if (nsec3OptOut)
				unsignedRecords = unsignedRecords.Union(subZoneNameserver.Where(x => !_records.Any(y => (y.RecordType == RecordType.Ds) && (y.Name == x.Name)))).ToList(); // delegations without DS record
			var recordsByName = _records.Except(unsignedRecords).Union(zoneSigningKeys).Union(keySigningKeys).GroupBy(x => x.Name).Select(x => new Tuple<DomainName, List<DnsRecordBase>>(x.Key, x.OrderBy(y => y.RecordType == RecordType.Soa ? -1 : (int) y.RecordType).ToList())).OrderBy(x => x.Item1).ToList();

			byte nsec3RecordFlags = (byte) (nsec3OptOut ? 1 : 0);

			Zone res = new Zone(Name, Count * 3);
			List<NSec3Record> nSec3Records = new List<NSec3Record>(Count);

			if (nsec3Salt == null)
				nsec3Salt = SecureRandom.GetSeed(8);

			recordsByName[0].Item2.Add(new NSec3ParamRecord(soaRecord.Name, soaRecord.RecordClass, 0, nsec3Algorithm, 0, (ushort) nsec3Iterations, nsec3Salt));

			HashSet<DomainName> allNames = new HashSet<DomainName>();

			for (int i = 0; i < recordsByName.Count; i++)
			{
				List<RecordType> recordTypes = new List<RecordType>();

				DomainName currentName = recordsByName[i].Item1;

				foreach (var recordsByType in recordsByName[i].Item2.GroupBy(x => x.RecordType))
				{
					List<DnsRecordBase> records = recordsByType.ToList();

					recordTypes.Add(recordsByType.Key);
					res.AddRange(records);

					// do not sign nameserver delegations for sub zones
					if ((records[0].RecordType == RecordType.Ns) && (currentName != Name))
						continue;

					recordTypes.Add(RecordType.RrSig);

					foreach (var key in zoneSigningKeys)
					{
						res.Add(new RrSigRecord(records, key, inception, expiration));
					}
					if (records[0].RecordType == RecordType.DnsKey)
					{
						foreach (var key in keySigningKeys)
						{
							res.Add(new RrSigRecord(records, key, inception, expiration));
						}
					}
				}

				byte[] hash = recordsByName[i].Item1.GetNSec3Hash(nsec3Algorithm, nsec3Iterations, nsec3Salt);
				nSec3Records.Add(new NSec3Record(DomainName.ParseFromMasterfile(hash.ToBase32HexString()) + Name, soaRecord.RecordClass, soaRecord.NegativeCachingTTL, nsec3Algorithm, nsec3RecordFlags, (ushort) nsec3Iterations, nsec3Salt, hash, recordTypes));

				allNames.Add(currentName);
				for (int j = currentName.LabelCount - Name.LabelCount; j > 0; j--)
				{
					DomainName possibleNonTerminal = currentName.GetParentName(j);

					if (!allNames.Contains(possibleNonTerminal))
					{
						hash = possibleNonTerminal.GetNSec3Hash(nsec3Algorithm, nsec3Iterations, nsec3Salt);
						nSec3Records.Add(new NSec3Record(DomainName.ParseFromMasterfile(hash.ToBase32HexString()) + Name, soaRecord.RecordClass, soaRecord.NegativeCachingTTL, nsec3Algorithm, nsec3RecordFlags, (ushort) nsec3Iterations, nsec3Salt, hash, new List<RecordType>()));

						allNames.Add(possibleNonTerminal);
					}
				}
			}

			nSec3Records = nSec3Records.OrderBy(x => x.Name).ToList();

			byte[] firstNextHashedOwnerName = nSec3Records[0].NextHashedOwnerName;

			for (int i = 1; i < nSec3Records.Count; i++)
			{
				nSec3Records[i - 1].NextHashedOwnerName = nSec3Records[i].NextHashedOwnerName;
			}

			nSec3Records[nSec3Records.Count - 1].NextHashedOwnerName = firstNextHashedOwnerName;

			foreach (var nSec3Record in nSec3Records)
			{
				res.Add(nSec3Record);

				foreach (var key in zoneSigningKeys)
				{
					res.Add(new RrSigRecord(new List<DnsRecordBase>() { nSec3Record }, key, inception, expiration));
				}
			}

			res.AddRange(unsignedRecords);

			return res;
		}


		/// <summary>
		///   Adds a record to the end of the Zone
		/// </summary>
		/// <param name="item">Record to be added</param>
		public void Add(DnsRecordBase item)
		{
			_records.Add(item);
		}

		/// <summary>
		///   Adds an enumeration of records to the end of the Zone
		/// </summary>
		/// <param name="items">Records to be added</param>
		public void AddRange(IEnumerable<DnsRecordBase> items)
		{
			_records.AddRange(items);
		}

		/// <summary>
		///   Removes all records from the zone
		/// </summary>
		public void Clear()
		{
			_records.Clear();
		}

		/// <summary>
		///   Determines whether a record is in the Zone
		/// </summary>
		/// <param name="item">Item which should be searched</param>
		/// <returns>true, if the item is in the zone; otherwise, false</returns>
		public bool Contains(DnsRecordBase item)
		{
			return _records.Contains(item);
		}

		/// <summary>
		///   Copies the entire Zone to a compatible array
		/// </summary>
		/// <param name="array">Array to which the records should be copied</param>
		/// <param name="arrayIndex">Starting index within the target array</param>
		public void CopyTo(DnsRecordBase[] array, int arrayIndex)
		{
			_records.CopyTo(array, arrayIndex);
		}

		/// <summary>
		///   Gets the number of records actually contained in the Zone
		/// </summary>
		public int Count => _records.Count;

		/// <summary>
		///   A value indicating whether the Zone is readonly
		/// </summary>
		/// <returns>false</returns>
		bool ICollection<DnsRecordBase>.IsReadOnly => false;

		/// <summary>
		///   Removes a record from the Zone
		/// </summary>
		/// <param name="item">Item to be removed</param>
		/// <returns>true, if the record was removed from the Zone; otherwise, false</returns>
		public bool Remove(DnsRecordBase item)
		{
			return _records.Remove(item);
		}

		/// <summary>
		///   Returns an enumerator that iterates through the records of the Zone
		/// </summary>
		/// <returns>An enumerator that iterates through the records of the Zone</returns>
		public IEnumerator<DnsRecordBase> GetEnumerator()
		{
			return _records.GetEnumerator();
		}

		/// <summary>
		///   Returns an enumerator that iterates through the records of the Zone
		/// </summary>
		/// <returns>An enumerator that iterates through the records of the Zone</returns>
		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}
	}
}