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

using System;
using System.Collections;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Class representing a DNS zone
	/// </summary>
	public class Zone : ICollection<DnsRecordBase>
	{
		private static readonly SecureRandom _secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

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

			SoaRecord? soa = (SoaRecord?) records.FirstOrDefault(x => x.RecordType == RecordType.Soa);

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
				var line = ReadRecordLine(reader);

				if (!String.IsNullOrWhiteSpace(line))
				{
					var parts = line.SplitWithQuoting(new[] { ' ', '\t' }, true, true).Select(x => x.FromMasterfileLabelRepresentation()).ToArray();

					if (parts[0].Equals("$origin", StringComparison.InvariantCultureIgnoreCase))
					{
						if (parts.Length != 2)
							throw new FormatException();

						origin = DomainName.ParseFromMasterfile(parts[1], origin);
					}
					else if (parts[0].Equals("$ttl", StringComparison.InvariantCultureIgnoreCase))
					{
						if (parts.Length != 2)
							throw new FormatException();

						ttl = Int32.Parse(parts[1]);
					}
					else if (parts[0].Equals("$include", StringComparison.InvariantCultureIgnoreCase))
					{
						if (reader.BaseStream is not FileStream fileStream)
							throw new NotSupportedException("Includes are only supported when loading files");

						// ReSharper disable once AssignNullToNotNullAttribute
						var path = Path.Combine(new FileInfo(fileStream!.Name).DirectoryName!, parts[1]);

						var includeOrigin = (parts.Length > 2) ? DomainName.ParseFromMasterfile(parts[2], origin) : origin;

						using var includeReader = new StreamReader(path);
						records.AddRange(ParseRecords(includeReader, includeOrigin, ttl, lastRecord));
					}
					else
					{
						string? domainString;
						RecordType recordType;
						RecordClass recordClass;
						int recordTtl;
						string[] rrData;

						// label ttl class type rd
						if (parts.Length >= 5
						    && Int32.TryParse(parts[1], out recordTtl)
						    && RecordClassHelper.TryParseShortString(parts[2], out recordClass, false)
						    && RecordTypeHelper.TryParseShortString(parts[3], out recordType))
						{
							domainString = parts[0];
							rrData = parts.Skip(4).ToArray();
						}
						// label class ttl type rd
						else if (parts.Length >= 5
						    && RecordClassHelper.TryParseShortString(parts[1], out recordClass, false)
						    && Int32.TryParse(parts[2], out recordTtl)
						    && RecordTypeHelper.TryParseShortString(parts[3], out recordType))
						{
							domainString = parts[0];
							rrData = parts.Skip(4).ToArray();
						}
						//       ttl class type rd
						else if (parts.Length >= 4
						    && Int32.TryParse(parts[0], out recordTtl)
						    && RecordClassHelper.TryParseShortString(parts[1], out recordClass, false)
						    && RecordTypeHelper.TryParseShortString(parts[2], out recordType))
						{
							domainString = null;
							rrData = parts.Skip(3).ToArray();
						}
						//       class ttl type rd
						else if (parts.Length >= 4
						         && RecordClassHelper.TryParseShortString(parts[0], out recordClass, false)
						         && Int32.TryParse(parts[1], out recordTtl)
						         && RecordTypeHelper.TryParseShortString(parts[2], out recordType))
						{
							domainString = null;
							rrData = parts.Skip(3).ToArray();
						}
						// label ttl       type rd
						else if (parts.Length >= 4
						         && Int32.TryParse(parts[1], out recordTtl)
						         && RecordTypeHelper.TryParseShortString(parts[2], out recordType))
						{
							domainString = parts[0];
							recordClass = RecordClass.Invalid;
							rrData = parts.Skip(3).ToArray();
						}
						// label     class type rd
						else if (parts.Length >= 4
						         && RecordClassHelper.TryParseShortString(parts[1], out recordClass, false)
						         && RecordTypeHelper.TryParseShortString(parts[2], out recordType))
						{
							domainString = parts[0];
							recordTtl = 0;
							rrData = parts.Skip(3).ToArray();
						}
						//       ttl       type rd
						else if (parts.Length >= 3
						         && Int32.TryParse(parts[0], out recordTtl)
						         && RecordTypeHelper.TryParseShortString(parts[1], out recordType))
						{
							domainString = null;
							recordClass = RecordClass.Invalid;
							rrData = parts.Skip(2).ToArray();
						}
						//           class type rd
						else if (parts.Length >= 3
						         && RecordClassHelper.TryParseShortString(parts[0], out recordClass, false)
						         && RecordTypeHelper.TryParseShortString(parts[1], out recordType))
						{
							domainString = null;
							recordTtl = 0;
							rrData = parts.Skip(2).ToArray();
						}
						//                 type rd
						else if (parts.Length >= 2
						         && RecordTypeHelper.TryParseShortString(parts[0], out recordType))
						{
							domainString = null;
							recordClass = RecordClass.Invalid;
							recordTtl = 0;
							rrData = parts.Skip(1).ToArray();
						}
						// label           type rd
						else if (parts.Length >= 3
						         && RecordTypeHelper.TryParseShortString(parts[1], out recordType))
						{
							domainString = parts[0];
							recordClass = RecordClass.Invalid;
							recordTtl = 0;
							rrData = parts.Skip(2).ToArray();
						}
						else
						{
							throw new FormatException("Could not parse line");
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
						else
						{
							domain = DomainName.ParseFromMasterfile(domainString, origin);
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

						lastRecord = DnsRecordBase.ParseFromStringRepresentation(domain, recordType, recordClass, recordTtl, origin, rrData);

						records.Add(lastRecord);
					}
				}
			}

			return records;
		}

		private static string? ReadRecordLine(StreamReader reader)
		{
			var line = ReadLineWithoutComment(reader);

			if (line == null)
				return null;

			int bracketPos;
			if ((bracketPos = line.IndexOfWithQuoting('(')) != -1)
			{
				StringBuilder sb = new StringBuilder();

				sb.Append(line.Substring(0, bracketPos));
				sb.Append(" ");
				sb.Append(line.Substring(bracketPos + 1));

				while (true)
				{
					sb.Append(" ");

					line = ReadLineWithoutComment(reader);

					if (line == null)
						return null;

					if ((bracketPos = line.IndexOfWithQuoting(')')) == -1)
					{
						sb.Append(line);
					}
					else
					{
						sb.Append(line[..bracketPos]);
						sb.Append(" ");
						sb.Append(line[(bracketPos + 1)..]);
						line = sb.ToString();
						break;
					}
				}
			}

			return line;
		}

		internal static string? ReadLineWithoutComment(StreamReader reader)
		{
			string? line = reader.ReadLine();

			if (line == null)
				return null;

			var index = line.IndexOfWithQuoting(';');

			return index < 0 ? line : line[..index];
		}

		/// <summary>
		/// Updates all supported ZONEMD records
		/// </summary>
		/// <param name="signingKeys">The signing keys, if the covering RRSIG records should be resigned.</param>
		public void UpdateZoneDigests(List<DnsKeyRecord>? signingKeys = null)
		{
			var zoneMdRecords = this.OfType<ZoneMDRecord>().Where(x => x.RecordType == RecordType.ZoneMD && x.Name.Equals(Name) && x.Scheme.IsSupported() && x.HashAlgorithm.IsSupported()).ToList();

			foreach (var record in zoneMdRecords)
			{
				record.UpdateDigest(this);
			}

			if (signingKeys != null && signingKeys.Count != 0)
			{
				foreach (var rrSigRecord in this.OfType<RrSigRecord>().Where(x => x.Name.Equals(Name) && x.TypeCovered == RecordType.ZoneMD))
				{
					rrSigRecord.Resign(this.Where(x => x.RecordType == RecordType.ZoneMD && x.Name.Equals(Name)).ToList(), signingKeys);
				}
			}
		}

		/// <summary>
		/// Validates a zone
		/// </summary>
		/// <param name="isDnsSecRequired">true, if the Zone needs to be signed</param>
		/// <param name="isZoneMdRequired">true, if the Zone needs to be covered by ZONEMD records</param>
		/// <param name="ignoreRecordErrors">true, if error in the zone records should be ignored</param>
		/// <returns></returns>
		public bool ValidateZone(bool isDnsSecRequired = false, bool isZoneMdRequired = false, bool ignoreRecordErrors = false)
		{
			var delegations = this.OfType<NsRecord>().Select(x => x.Name).Where(x => !x.Equals(Name)).ToHashSet();

			var glueRecords = this.Where(
				r => delegations.Any(d => r.Name.IsSubDomainOf(d))
				     || delegations.Any(d => r.Name.Equals(d) && !r.RecordType.IsAnyOf(RecordType.Ns, RecordType.RrSig, RecordType.NSec, RecordType.Ds))).ToArray();

			var zoneRecords = this.Where(r => !glueRecords.Any(r.Equals));

			var recordsByName = new SortedMultiDimensionalLookup<DomainName, RecordType, DnsRecordBase>(zoneRecords, x => x.Name, x => x.RecordType);

			var soa = recordsByName[Name][RecordType.Soa].Cast<SoaRecord>().FirstOrDefault();

			return (ignoreRecordErrors || ValidateZoneRecords(delegations, glueRecords, recordsByName))
			       && ValidateDnsSec(delegations, glueRecords, recordsByName, isDnsSecRequired)
			       && ValidateZoneDigest(delegations, glueRecords, recordsByName, isZoneMdRequired);
		}

		internal bool ValidateZoneRecords(HashSet<DomainName> delegations, DnsRecordBase[] glueRecords, SortedMultiDimensionalLookup<DomainName, RecordType, DnsRecordBase> recordsByName)
		{
			SoaRecord? soa = recordsByName[Name][RecordType.Soa].Cast<SoaRecord>().SingleOrDefaultIfMultiple();

			// Zone Apex requires exactly one SOA
			if (soa == null)
				return false;

			// SOA name must be zone Name
			if (!soa.Name.Equals(Name))
				return false;


			// SOA is only allowed on zone apex
			if (recordsByName.Where(x => x.Key.IsSubDomainOf(Name)).Any(x => x.Value.Contains(RecordType.Soa)))
				return false;

			// check if there is any out of zone record
			if (recordsByName.Any(x => !x.Key.IsEqualOrSubDomainOf(Name)))
				return false;

			// check for sub-delegations
			if (delegations.Any(p => delegations.Any(s => s.IsSubDomainOf(p))))
				return false;

			// Only A and AAAA are allowed for glue records (NS,DS,RRSIG and NSEC are part of parental zone)
			if (glueRecords.Any(x => !x.RecordType.IsAnyOf(RecordType.A, RecordType.Aaaa)))
				return false;

			foreach (var nameSet in recordsByName)
			{
				var name = nameSet.Key;
				var rrset = nameSet.Value;

				if (!name.IsEqualOrSubDomainOf(Name))
					return false;

				if (rrset.Contains(RecordType.CName))
				{
					// only single CNAME is allowed
					if (rrset[RecordType.CName].Count() > 1)
						return false;

					// no other records are allowed on CNAME, except RRSIG and NSEC
					if (rrset.Any(x=>!x.Key.IsAnyOf(RecordType.CName, RecordType.RrSig, RecordType.NSec)))
						return false;
				}
			}

			return true;
		}

		internal bool ValidateDnsSec(HashSet<DomainName> delegations, DnsRecordBase[] glueRecords, SortedMultiDimensionalLookup<DomainName, RecordType, DnsRecordBase> recordsByName, bool isDnsSecRequired)
		{
			var dnsKeys = recordsByName[Name][RecordType.DnsKey].Cast<DnsKeyRecord>().Where(k => k.IsZoneKey && k.Protocol == 3).ToArray();

			if (dnsKeys.Length == 0 && !recordsByName.Any(x=>x.Value.Contains(RecordType.RrSig)))
				return !isDnsSecRequired;

			if (dnsKeys.Count(x => x.IsSecureEntryPoint) == 0)
				return false;

			var keyTags = dnsKeys.Select(x => x.CalculateKeyTag()).ToHashSet();

			var nsec3params = recordsByName[Name][RecordType.NSec3Param].Cast<NSec3ParamRecord>().ToArray();
			if (nsec3params.Length > 1)
				return false;

			var nsec3param = nsec3params.FirstOrDefault();

			var nsec3Records = recordsByName.SelectMany(x => x.Value[RecordType.NSec3]).Cast<NSec3Record>().OrderBy(x => x.Name).ToArray();

			var recordHashes = new List<DomainName>();

			for (var i = 0; i < recordsByName.Count; i++)
			{
				var set = recordsByName[i];

				// check RRSIG, if it is not a glue record
				if (!delegations.Any(delegation => set.Key.IsSubDomainOf(delegation)))
				{
					var typedSets = set.Value;
					var coveredTypes = new HashSet<RecordType>();

					foreach (var rrsig in typedSets[RecordType.RrSig].Cast<RrSigRecord>())
					{
						if (!keyTags.Contains(rrsig.KeyTag))
							return false;

						if (!rrsig.Verify(typedSets[rrsig.TypeCovered].ToList(), dnsKeys))
							return false;

						coveredTypes.Add(RecordType.RrSig);
						coveredTypes.Add(rrsig.TypeCovered);
					}

					if (!set.Key.Equals(Name) && typedSets.Contains(RecordType.Ns))
						coveredTypes.Add(RecordType.Ns);

					if (typedSets.Any(typedSet => !coveredTypes.Contains(typedSet.Key)))
						return false;

					if (typedSets[RecordType.NSec].Count() > 1)
						return false;

					if (typedSets[RecordType.NSec3].Count() > 1)
						return false;

					if (nsec3param != null)
					{
						// check NSEC3 records of empty parent labels
						if (set.Key.IsSubDomainOf(Name))
						{
							var parent = set.Key.GetParentName();
							while (recordsByName[parent].Count == 0)
							{
								if (!recordsByName.TryGetValue(parent.GetNSec3HashName(nsec3param.HashAlgorithm, nsec3param.Iterations, nsec3param.Salt, Name), RecordType.NSec3, out var parentHashOwnerSet))
									return false;

								var nsec3 = parentHashOwnerSet.Cast<NSec3Record>().FirstOrDefault();

								if (nsec3 == null)
									return false;

								if (nsec3.Types.Any())
									return false;

								parent = parent.GetParentName();
							}
						}

						var nsec3hashname = set.Key.GetNSec3HashName(nsec3param.HashAlgorithm, nsec3param.Iterations, nsec3param.Salt, Name);

						// check covering NSEC3 records, if set contains more than just the NSEC3 record
						if (!coveredTypes.OrderBy(x => x).SequenceEqual(new [] { RecordType.RrSig ,RecordType.NSec3}))
						{
							if (recordsByName.TryGetValue(nsec3hashname, RecordType.NSec3, out var nextHashOwnerSet))
							{
								// there is a rrset on the next hash owner, check if it contains a matching NSEC3 record
								var nsec3 = nextHashOwnerSet.Cast<NSec3Record>().FirstOrDefault();

								if (nsec3 == null)
									return false;

								if (!nsec3.Types.OrderBy(x => x).SequenceEqual(coveredTypes.Where(x => x != RecordType.NSec3).OrderBy(x => x)))
									return false;

								recordHashes.Add(nsec3hashname);
							}
							else
							{
								// No matching next hash owner rrset, check for opt-out
								var coveringNSec3 = nsec3Records.FirstOrDefault(x => x.IsCovering(nsec3hashname));

								if (coveringNSec3 == null)
									return false;

								if (!coveringNSec3.Flags.HasFlag(NSec3Flags.OptOut))
									return false;
							}
						}
					}
					else
					{
						var nsec = typedSets[RecordType.NSec].Cast<NSecRecord>().FirstOrDefault();

						if (nsec == null) 
							return false;

						if (!nsec.Types.OrderBy(x => x).SequenceEqual(coveredTypes.OrderBy(x => x)))
							return false;

						if (!nsec.NextDomainName.Equals(recordsByName[(i + 1) % recordsByName.Count].Key))
							return false;
					}
				}
			}

			if (nsec3param != null)
			{
				//check for NSEC3 chain
				for (var i = 0; i < nsec3Records.Length; i++)
				{
					if (!nsec3Records[i].NextHashedOwnerName.Equals(nsec3Records[(i + 1) % nsec3Records.Length].Name))
						return false;
				}

				if (!recordHashes.OrderBy(x => x).SequenceEqual(nsec3Records.Where(x=>x.Types.Any()).Select(x => x.Name)))
					return false;
			}


			return true;
		}

		internal bool ValidateZoneDigest(HashSet<DomainName> delegations, DnsRecordBase[] glueRecords, SortedMultiDimensionalLookup<DomainName, RecordType, DnsRecordBase> recordsByName, bool isValidDigestRequired = false)
		{
			var zoneMDs = recordsByName[Name][RecordType.ZoneMD].OfType<ZoneMDRecord>().Where(x => x.HashAlgorithm.IsSupported() && x.Scheme.IsSupported()).ToArray();

			if (zoneMDs.Any())
			{
				SoaRecord? soa = recordsByName[Name][RecordType.Soa].Cast<SoaRecord>().SingleOrDefaultIfMultiple();

				// a SOA record is needed for validation of ZONEMD record
				if (soa == null)
					return false;

				//var zoneBuffer = GetSimpleZoneDigestBuffer();

				foreach (var group in zoneMDs.GroupBy(x => new { x.Scheme, x.HashAlgorithm }))
				{
					if (group.Take(2).Count() != 1)
						continue;

					var record = group.First();

					if (record.SerialNumber != soa.SerialNumber)
						continue;

					if (record.Validate(this))
						return true;
				}

				return false;
			}

			return !isValidDigestRequired;
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
		/// <param name="updateZoneDigests">true, if ZONEMD records should be updated while signing</param>
		/// <returns>A signed zone</returns>
		public Zone Sign(List<DnsKeyRecord> keys, DateTime inception, DateTime expiration, NSec3HashAlgorithm nsec3Algorithm = 0, int nsec3Iterations = 10, byte[]? nsec3Salt = null, bool nsec3OptOut = false, bool updateZoneDigests = true)
		{
			if ((keys == null) || (keys.Count == 0))
				throw new Exception("No DNS Keys were provided");

			if (!keys.All(x => x.IsZoneKey))
				throw new Exception("No DNS key with Zone Key Flag were provided");

			if (keys.Any(x => (x.PrivateKey == null) || (x.PrivateKey.Length == 0)))
				throw new Exception("For at least one DNS key no Private Key was provided");

			if (keys.Any(x => (x.Protocol != 3) || ((nsec3Algorithm != 0) ? !x.Algorithm.IsCompatibleWithNSec3() : !x.Algorithm.IsCompatibleWithNSec())))
				throw new Exception("At least one invalid DNS key was provided");

			DnsKeyRecord[] keySigningKeys = keys.Where(x => x.IsSecureEntryPoint).ToArray();
			DnsKeyRecord[] zoneSigningKeys = keys.Where(x => !x.IsSecureEntryPoint).ToArray();

			if (zoneSigningKeys.Length == 0)
			{
				zoneSigningKeys = keySigningKeys;
				keySigningKeys = Array.Empty<DnsKeyRecord>();
			}

			Zone res;

			if (nsec3Algorithm == 0)
			{
				res = SignWithNSec(inception, expiration, zoneSigningKeys, keySigningKeys);
			}
			else
			{
				res = SignWithNSec3(inception, expiration, zoneSigningKeys, keySigningKeys, nsec3Algorithm, nsec3Iterations, nsec3Salt, nsec3OptOut);
			}

			if (updateZoneDigests)
				res.UpdateZoneDigests(keys);

			return res;
		}

		private Zone SignWithNSec(DateTime inception, DateTime expiration, DnsKeyRecord[] zoneSigningKeys, DnsKeyRecord[] keySigningKeys)
		{
			var soaRecord = _records.OfType<SoaRecord>().First();
			var subZones = _records.Where(x => (x.RecordType == RecordType.Ns) && !x.Name.Equals(Name)).Select(x => x.Name).Distinct().ToList();
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
					if ((records[0].RecordType == RecordType.Ns) && !currentName.Equals(Name))
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
				recordTypes.Add(RecordType.RrSig);

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

		private Zone SignWithNSec3(DateTime inception, DateTime expiration, DnsKeyRecord[] zoneSigningKeys, DnsKeyRecord[] keySigningKeys, NSec3HashAlgorithm nsec3Algorithm, int nsec3Iterations, byte[]? nsec3Salt, bool nsec3OptOut)
		{
			var soaRecord = _records.OfType<SoaRecord>().First();
			var subZoneNameserver = _records.Where(x => (x.RecordType == RecordType.Ns) && !x.Name.Equals(Name)).ToList();
			var subZones = subZoneNameserver.Select(x => x.Name).Distinct().ToList();
			var unsignedRecords = _records.Where(x => subZones.Any(y => x.Name.IsSubDomainOf(y))).ToList(); // glue records
			if (nsec3OptOut)
				unsignedRecords = unsignedRecords.Union(subZoneNameserver.Where(x => !_records.Any(y => (y.RecordType == RecordType.Ds) && y.Name.Equals(x.Name)))).ToList(); // delegations without DS record
			var recordsByName = _records.Except(unsignedRecords).Union(zoneSigningKeys).Union(keySigningKeys).GroupBy(x => x.Name).Select(x => new Tuple<DomainName, List<DnsRecordBase>>(x.Key, x.OrderBy(y => y.RecordType == RecordType.Soa ? -1 : (int) y.RecordType).ToList())).OrderBy(x => x.Item1).ToList();

			NSec3Flags nsec3RecordFlags = nsec3OptOut ? NSec3Flags.OptOut : NSec3Flags.None;

			Zone res = new Zone(Name, Count * 3);
			List<NSec3Record> nSec3Records = new List<NSec3Record>(Count);

			if (nsec3Salt == null)
				nsec3Salt = _secureRandom.GenerateSeed(8);

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
					if ((records[0].RecordType == RecordType.Ns) && !currentName.Equals(Name))
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

				var nsec3Hash = recordsByName[i].Item1.GetNSec3Hash(nsec3Algorithm, nsec3Iterations, nsec3Salt);
				nSec3Records.Add(new NSec3Record(new DomainName(nsec3Hash.ToBase32HexString(), Name), soaRecord.RecordClass, soaRecord.NegativeCachingTTL, nsec3Algorithm, nsec3RecordFlags, (ushort) nsec3Iterations, nsec3Salt, nsec3Hash, recordTypes));

				allNames.Add(currentName);
				for (int j = currentName.LabelCount - Name.LabelCount; j > 0; j--)
				{
					var possibleNonTerminal = currentName.GetParentName(j);

					if (!allNames.Contains(possibleNonTerminal))
					{
						nsec3Hash = possibleNonTerminal.GetNSec3Hash(nsec3Algorithm, nsec3Iterations, nsec3Salt);
						nSec3Records.Add(new NSec3Record(new DomainName(nsec3Hash.ToBase32HexString(), Name), soaRecord.RecordClass, soaRecord.NegativeCachingTTL, nsec3Algorithm, nsec3RecordFlags, (ushort) nsec3Iterations, nsec3Salt, nsec3Hash, new List<RecordType>()));

						allNames.Add(possibleNonTerminal);
					}
				}
			}

			nSec3Records = nSec3Records.OrderBy(x => x.Name).ToList();

			byte[] firstNextHashedOwnerName = nSec3Records[0].NextHashedOwner;

			for (int i = 1; i < nSec3Records.Count; i++)
			{
				nSec3Records[i - 1].NextHashedOwner = nSec3Records[i].NextHashedOwner;
			}

			nSec3Records[nSec3Records.Count - 1].NextHashedOwner = firstNextHashedOwnerName;

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