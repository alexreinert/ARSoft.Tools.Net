using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net.Dns;

/// <summary>
///   <para>ZONEMD record</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc8976.html">RFC 8976</a>.
///   </para>
/// </summary>
// ReSharper disable once InconsistentNaming
public class ZoneMDRecord : DnsRecordBase
{
	/// <summary>
	///   ZONEMD scheme
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public enum ZoneMDScheme : byte
	{
		/// <summary>
		///   <para>Simple ZONEMD collation</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8976.html">RFC 8976</a>.
		///   </para>
		/// </summary>
		Simple = 1,
	}

	/// <summary>
	///   ZONEMD hash algorithm
	/// </summary>
	// ReSharper disable once InconsistentNaming
	public enum ZoneMDHashAlgorithm : byte
	{
		/// <summary>
		///   <para>SHA-384</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8976.html">RFC 8976</a>.
		///   </para>
		/// </summary>
		Sha384 = 1,

		/// <summary>
		///   <para>SHA-512</para>
		///   <para>
		///     Defined in
		///     <a href="https://www.rfc-editor.org/rfc/rfc8976.html">RFC 8976</a>.
		///   </para>
		/// </summary>
		Sha512 = 2,
	}

	/// <summary>
	///   Serial number of the zone
	/// </summary>
	public uint SerialNumber { get; private set; }

	/// <summary>
	///   Scheme
	/// </summary>
	public ZoneMDScheme Scheme { get; }

	/// <summary>
	///   Hash algorithm
	/// </summary>
	public ZoneMDHashAlgorithm HashAlgorithm { get; }

	/// <summary>
	///   Digest
	/// </summary>
	public byte[] Digest { get; private set; }


	internal ZoneMDRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, IList<byte> resultData, int currentPosition, int length)
		: base(name, recordType, recordClass, timeToLive)
	{
		SerialNumber = DnsMessageBase.ParseUInt(resultData, ref currentPosition);
		Scheme = (ZoneMDScheme)resultData[currentPosition++];
		HashAlgorithm = (ZoneMDHashAlgorithm)resultData[currentPosition++];
		Digest = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length - 6);
	}

	internal ZoneMDRecord(DomainName name, RecordType recordType, RecordClass recordClass, int timeToLive, DomainName origin, string[] stringRepresentation)
		: base(name, recordType, recordClass, timeToLive)
	{
		if (stringRepresentation.Length < 4)
			throw new FormatException();

		SerialNumber = UInt32.Parse(stringRepresentation[0]);
		Scheme = (ZoneMDScheme)Byte.Parse(stringRepresentation[1]);
		HashAlgorithm = (ZoneMDHashAlgorithm)Byte.Parse(stringRepresentation[2]);
		Digest = String.Join(String.Empty, stringRepresentation.Skip(3)).FromBase16String();
	}

	/// <summary>
	///   Creates a new instance of the X25Record class
	/// </summary>
	/// <param name="name"> Name of the record </param>
	/// <param name="timeToLive"> Seconds the record should be cached at most </param>
	/// <param name="serialNumber">Serial number of the zone</param>
	/// <param name="scheme">Used ZONEMD scheme</param>
	/// <param name="hashAlgorithm">Used hash algorithm</param>
	/// <param name="digest">Digest</param>
	public ZoneMDRecord(DomainName name, int timeToLive, uint serialNumber, ZoneMDScheme scheme, ZoneMDHashAlgorithm hashAlgorithm, byte[] digest)
		: base(name, RecordType.ZoneMD, RecordClass.INet, timeToLive)
	{
		SerialNumber = serialNumber;
		Scheme = scheme;
		HashAlgorithm = hashAlgorithm;
		Digest = digest;
	}

	internal override string RecordDataToString()
	{
		return SerialNumber
		       + " " + (byte)Scheme
		       + " " + (byte)HashAlgorithm
		       + " " + Digest.ToBase16String();
	}

	protected internal override int MaximumRecordDataLength => 6 + Digest.Length;

	protected internal override void EncodeRecordData(IList<byte> messageData, ref int currentPosition, Dictionary<DomainName, ushort>? domainNames, bool useCanonical)
	{
		DnsMessageBase.EncodeUInt(messageData, ref currentPosition, SerialNumber);
		messageData[currentPosition++] = (byte)Scheme;
		messageData[currentPosition++] = (byte)HashAlgorithm;
		DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Digest);
	}

	internal void UpdateDigest(Zone zone)
	{
		var soa = zone.OfType<SoaRecord>().First();
		this.SerialNumber = soa.SerialNumber;
		this.Digest = CalculateZoneMDDigest(zone);
	}

	internal bool Validate(Zone zone)
	{
		var calculated = CalculateZoneMDDigest(zone);
		return Digest.SequenceEqual(calculated);
	}

	private byte[] CalculateZoneMDDigest(Zone zone)
	{
		IDigest digest;
		switch (HashAlgorithm)
		{
			case ZoneMDRecord.ZoneMDHashAlgorithm.Sha384:
				digest = new Sha384Digest();
				break;
			case ZoneMDRecord.ZoneMDHashAlgorithm.Sha512:
				digest = new Sha512Digest();
				break;
			default:
				digest = new NullDigest();
				break;
		}

		DnsRecordBase lastRecord = new UnknownRecord(DomainName.Root, RecordType.Invalid, RecordClass.None, 0, Array.Empty<byte>());

		foreach (var record in zone.OrderBy(x => x))
		{
			// ignore out of zone data
			if (!record.Name.IsEqualOrSubDomainOf(Name))
				continue;

			// ignore duplicates
			if (record.Equals(lastRecord))
				continue;

			// ignore ZONEMD records at zone apex
			if (record.Name.Equals(Name) && record.RecordType == RecordType.ZoneMD)
				continue;

			// ignore RRSIG records covering ZONEMD records at zone apex
			if (record.Name.Equals(Name) && record.RecordType == RecordType.RrSig && ((RrSigRecord)record).TypeCovered == RecordType.ZoneMD)
				continue;

			lastRecord = record;

			var buffer = new byte[record.MaximumLength];
			var pos = 0;

			record.Encode(buffer, ref pos, null, true);

			digest.BlockUpdate(buffer, 0, pos);
		}

		byte[] hash = new byte[digest.GetDigestSize()];
		digest.DoFinal(hash, 0);

		return hash;
	}

}

internal static class ZoneMDHelper
{
	public static bool IsSupported(this ZoneMDRecord.ZoneMDHashAlgorithm hashAlgorithm)
	{
		switch (hashAlgorithm)
		{
			case ZoneMDRecord.ZoneMDHashAlgorithm.Sha384:
			case ZoneMDRecord.ZoneMDHashAlgorithm.Sha512:
				return true;

			default:
				return false;
		}
	}

	public static bool IsSupported(this ZoneMDRecord.ZoneMDScheme scheme)
	{
		switch (scheme)
		{
			case ZoneMDRecord.ZoneMDScheme.Simple:
				return true;

			default:
				return false;
		}
	}

}