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

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Dns.DnsRecord
{
    /// <summary>
    ///   <para>Location information</para>
    ///   <para>
    ///     Defined in
    ///     <see cref="!:http://tools.ietf.org/html/rfc1876">RFC 1876</see>
    ///   </para>
    /// </summary>
    public class LocRecord : DnsRecordBase
	{
		private static readonly Regex _parserRegex = new Regex(@"^(?<latd>\d{1,2})( (?<latm>\d{1,2})( (?<lats>\d{1,2})(\.(?<latms>\d{1,3}))?)?)? (?<lat>(N|S)) (?<longd>\d{1,2})( (?<longm>\d{1,2})( (?<longs>\d{1,2})(\.(?<longms>\d{1,3}))?)?)? (?<long>(W|E)) (?<alt>-?\d{1,2}(\.\d+)?)m?( (?<size>\d+(\.\d+)?)m?( (?<hp>\d+(\.\d+)?)m?( (?<vp>\d+(\.\d+)?)m?)?)?)?$", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled);

		/// <summary>
		///   Represents a geopgraphical degree
		/// </summary>
		public class Degree
		{
			/// <summary>
			///   Is negative value
			/// </summary>
			public bool IsNegative { get; }

			/// <summary>
			///   Number of full degrees
			/// </summary>
			public int Degrees { get; }

			/// <summary>
			///   Number of minutes
			/// </summary>
			public int Minutes { get; }

			/// <summary>
			///   Number of seconds
			/// </summary>
			public int Seconds { get; }

			/// <summary>
			///   Number of Milliseconds
			/// </summary>
			public int Milliseconds { get; }

			/// <summary>
			///   Returns the decimal representation of the Degree instance
			/// </summary>
			public double DecimalDegrees => (IsNegative ? -1d : 1d) * (Degrees + (double) Minutes / 6000 * 100 + (Seconds + (double) Milliseconds / 1000) / 360000 * 100);

			/// <summary>
			///   Creates a new instance of the Degree class
			/// </summary>
			/// <param name="isNegative"> Is negative value </param>
			/// <param name="degrees"> Number of full degrees </param>
			/// <param name="minutes"> Number of minutes </param>
			/// <param name="seconds"> Number of seconds </param>
			/// <param name="milliseconds"> Number of Milliseconds </param>
			public Degree(bool isNegative, int degrees, int minutes, int seconds, int milliseconds)
			{
				IsNegative = isNegative;
				Degrees = degrees;
				Minutes = minutes;
				Seconds = seconds;
				Milliseconds = milliseconds;
			}

			internal Degree(bool isNegative, string degrees, string minutes, string seconds, string milliseconds)
			{
				IsNegative = isNegative;

				Degrees = int.Parse(degrees);
				Minutes = int.Parse(minutes.PadLeft(1, '0'));
				Seconds = int.Parse(seconds.PadLeft(1, '0'));
				Milliseconds = int.Parse(milliseconds.PadRight(3, '0'));
			}

			/// <summary>
			///   Creates a new instance of the Degree class
			/// </summary>
			/// <param name="decimalDegrees"> Decimal representation of the Degree </param>
			public Degree(double decimalDegrees)
			{
				if (decimalDegrees < 0)
				{
					IsNegative = true;
					decimalDegrees = -decimalDegrees;
				}

				Degrees = (int) decimalDegrees;
				decimalDegrees -= Degrees;
				decimalDegrees *= 60;
				Minutes = (int) decimalDegrees;
				decimalDegrees -= Minutes;
				decimalDegrees *= 60;
				Seconds = (int) decimalDegrees;
				decimalDegrees -= Seconds;
				decimalDegrees *= 1000;
				Milliseconds = (int) decimalDegrees;
			}

			private string ToDegreeString()
			{
				var res = string.Empty;

				if (Milliseconds != 0)
					res = "." + Milliseconds.ToString().PadLeft(3, '0').TrimEnd('0');

				if (res.Length > 0 || Seconds != 0)
					res = " " + Seconds + res;

				if (res.Length > 0 || Minutes != 0)
					res = " " + Minutes + res;

				res = Degrees + res;

				return res;
			}

			internal string ToLatitudeString() => ToDegreeString() + " " + (IsNegative ? "S" : "N");

		    internal string ToLongitudeString() => ToDegreeString() + " " + (IsNegative ? "W" : "E");
		}

		/// <summary>
		///   Version number of representation
		/// </summary>
		public byte Version { get; private set; }

		/// <summary>
		///   Size of location in centimeters
		/// </summary>
		public double Size { get; private set; }

		/// <summary>
		///   Horizontal precision in centimeters
		/// </summary>
		public double HorizontalPrecision { get; private set; }

		/// <summary>
		///   Vertical precision in centimeters
		/// </summary>
		public double VerticalPrecision { get; private set; }

		/// <summary>
		///   Latitude of the geographical position
		/// </summary>
		public Degree Latitude { get; private set; }

		/// <summary>
		///   Longitude of the geographical position
		/// </summary>
		public Degree Longitude { get; private set; }

		/// <summary>
		///   Altitude of the geographical position
		/// </summary>
		public double Altitude { get; private set; }

		internal LocRecord() {}

		/// <summary>
		///   Creates a new instance of the LocRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="version"> Version number of representation </param>
		/// <param name="size"> Size of location in centimeters </param>
		/// <param name="horizontalPrecision"> Horizontal precision in centimeters </param>
		/// <param name="verticalPrecision"> Vertical precision in centimeters </param>
		/// <param name="latitude"> Latitude of the geographical position </param>
		/// <param name="longitude"> Longitude of the geographical position </param>
		/// <param name="altitude"> Altitude of the geographical position </param>
		public LocRecord(DomainName name, int timeToLive, byte version, double size, double horizontalPrecision, double verticalPrecision, Degree latitude, Degree longitude, double altitude)
			: base(name, RecordType.Loc, RecordClass.INet, timeToLive)
		{
			Version = version;
			Size = size;
			HorizontalPrecision = horizontalPrecision;
			VerticalPrecision = verticalPrecision;
			Latitude = latitude;
			Longitude = longitude;
			Altitude = altitude;
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			Version = resultData[currentPosition++];
			Size = ConvertPrecision(resultData[currentPosition++]);
			HorizontalPrecision = ConvertPrecision(resultData[currentPosition++]);
			VerticalPrecision = ConvertPrecision(resultData[currentPosition++]);
			Latitude = ConvertDegree(DnsMessageBase.ParseInt(resultData, ref currentPosition));
			Longitude = ConvertDegree(DnsMessageBase.ParseInt(resultData, ref currentPosition));
			Altitude = ConvertAltitude(DnsMessageBase.ParseInt(resultData, ref currentPosition));
		}

		internal override void ParseRecordData(DomainName origin, string[] stringRepresentation)
		{
			var groups = _parserRegex
				.Match(string.Join(" ", stringRepresentation))
				.Groups;

			var latNegative = groups["lat"].Value.Equals("S", StringComparison.InvariantCultureIgnoreCase);
			Latitude = new Degree(latNegative, groups["latd"].Value, groups["latm"].Value, groups["lats"].Value, groups["latms"].Value);

			var longNegative = groups["long"].Value.Equals("W", StringComparison.InvariantCultureIgnoreCase);
			Longitude = new Degree(longNegative, groups["longd"].Value, groups["longm"].Value, groups["longs"].Value, groups["longms"].Value);

			Altitude = double.Parse(groups["alt"].Value, CultureInfo.InvariantCulture);
			Size = string.IsNullOrEmpty(groups["size"].Value) ? 1 : double.Parse(groups["size"].Value, CultureInfo.InvariantCulture);
			HorizontalPrecision = string.IsNullOrEmpty(groups["hp"].Value) ? 10000 : double.Parse(groups["hp"].Value, CultureInfo.InvariantCulture);
			VerticalPrecision = string.IsNullOrEmpty(groups["vp"].Value) ? 10 : double.Parse(groups["vp"].Value, CultureInfo.InvariantCulture);
		}

		[SuppressMessage("ReSharper", "CompareOfFloatsByEqualityOperator")]
		internal override string RecordDataToString() => Latitude.ToLatitudeString()
		                                                 + " "
		                                                 + Longitude.ToLongitudeString()
		                                                 + " " + Altitude.ToString(CultureInfo.InvariantCulture) + "m"
		                                                 + (Size != 1 || HorizontalPrecision != 10000 || VerticalPrecision != 10 ? " " + Size + "m" : "")
		                                                 + (HorizontalPrecision != 10000 || VerticalPrecision != 10 ? " " + HorizontalPrecision + "m" : "")
		                                                 + (VerticalPrecision != 10 ? " " + VerticalPrecision + "m" : "");

	    protected internal override int MaximumRecordDataLength => 16;



        protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<DomainName, ushort> domainNames, bool useCanonical)
		{
			messageData[currentPosition++] = Version;
			messageData[currentPosition++] = ConvertPrecision(Size);
			messageData[currentPosition++] = ConvertPrecision(HorizontalPrecision);
			messageData[currentPosition++] = ConvertPrecision(VerticalPrecision);
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, ConvertDegree(Latitude));
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, ConvertDegree(Longitude));
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, ConvertAltitude(Altitude));
		}

		#region Convert Precision
		private static readonly int[] _powerOften = new int[] { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

		private static double ConvertPrecision(byte precision)
		{
			var mantissa = (precision >> 4 & 0x0f) % 10;
			var exponent = (precision & 0x0f) % 10;
			return mantissa * (double) _powerOften[exponent] / 100;
		}

		private static byte ConvertPrecision(double precision)
		{
			var centimeters = precision * 100;

			int exponent;
			for (exponent = 0; exponent < 9; exponent++)
			    if (centimeters < _powerOften[exponent + 1])
			        break;

		    var mantissa = (int) (centimeters / _powerOften[exponent]);
			if (mantissa > 9)
				mantissa = 9;

			return (byte) (mantissa << 4 | exponent);
		}
		#endregion

		#region Convert Degree
		private static Degree ConvertDegree(int degrees)
		{
			degrees -= 1 << 31;

			bool isNegative;
			if (degrees < 0)
			{
				isNegative = true;
				degrees = -degrees;
			}
			else
			    isNegative = false;

		    var milliseconds = degrees % 1000;
			degrees /= 1000;
			var seconds = degrees % 60;
			degrees /= 60;
			var minutes = degrees % 60;
			degrees /= 60;

			return new Degree(isNegative, degrees, minutes, seconds, milliseconds);
		}

		private static int ConvertDegree(Degree degrees)
		{
			var res = degrees.Degrees * 3600000 + degrees.Minutes * 60000 + degrees.Seconds * 1000 + degrees.Milliseconds;

			if (degrees.IsNegative)
				res = -res;

			return res + (1 << 31);
		}
		#endregion

		#region Convert Altitude
		private const int _ALTITUDE_REFERENCE = 10000000;

		private static double ConvertAltitude(int altitude) => (altitude < _ALTITUDE_REFERENCE ? (_ALTITUDE_REFERENCE - altitude) * -1 : altitude - _ALTITUDE_REFERENCE) / 100d;

	    private static int ConvertAltitude(double altitude)
		{
			var centimeter = (int) (altitude * 100);
			return centimeter > 0 ? _ALTITUDE_REFERENCE + centimeter : centimeter + _ALTITUDE_REFERENCE;
		}
		#endregion
	}
}