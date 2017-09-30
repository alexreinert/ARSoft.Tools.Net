#region Copyright and License
// Copyright 2010..11 Alexander Reinert
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
using System.Globalization;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	public class LocRecord : DnsRecordBase
	{
		public class Degree
		{
			public bool IsNegative { get; private set; }
			public int Degrees { get; private set; }
			public int Minutes { get; private set; }
			public int Seconds { get; private set; }
			public int Milliseconds { get; private set; }

			public double DecimalDegrees
			{
				get { return (IsNegative ? -1d : 1d) * (Degrees + (double) Minutes / 6000 * 100 + (Seconds + (double) Milliseconds / 1000) / 360000 * 100); }
			}

			public Degree(bool isNegative, int degrees, int minutes, int seconds, int milliseconds)
			{
				IsNegative = isNegative;
				Degrees = degrees;
				Minutes = minutes;
				Seconds = seconds;
				Milliseconds = milliseconds;
			}

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
		}

		public byte Version { get; private set; }
		public double Size { get; private set; }
		public double HorizontalPrecision { get; private set; }
		public double VerticalPrecision { get; private set; }
		public Degree Latitude { get; private set; }
		public Degree Longitude { get; private set; }
		public double Altitude { get; private set; }

		internal LocRecord() {}

		public LocRecord(string name, int timeToLive, byte version, double size, double horizontalPrecision, double verticalPrecision, Degree latitude, Degree longitude, double altitude)
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

		internal override string RecordDataToString()
		{
			return Latitude.Degrees
			       + (((Latitude.Minutes != 0) || (Latitude.Seconds != 0) || (Latitude.Milliseconds != 0)) ? " " + Latitude.Minutes : "")
			       + (((Latitude.Seconds != 0) || (Latitude.Milliseconds != 0)) ? " " + Latitude.Seconds : "")
			       + ((Latitude.Milliseconds != 0) ? "." + Latitude.Milliseconds : "")
			       + " " + (Latitude.IsNegative ? "S" : "N")
			       + " " + Longitude.Degrees
			       + (((Longitude.Minutes != 0) || (Longitude.Seconds != 0) || (Longitude.Milliseconds != 0)) ? " " + Longitude.Minutes : "")
			       + (((Longitude.Seconds != 0) || (Longitude.Milliseconds != 0)) ? " " + Longitude.Seconds : "")
			       + ((Longitude.Milliseconds != 0) ? "." + Longitude.Milliseconds : "")
			       + " " + (Longitude.IsNegative ? "W" : "E")
			       + " " + Altitude.ToString(CultureInfo.InvariantCulture) + "m"
			       + (((Size != 1) || (HorizontalPrecision != 10000) || (VerticalPrecision != 10)) ? " " + Size + "m" : "")
			       + (((HorizontalPrecision != 10000) || (VerticalPrecision != 10)) ? " " + HorizontalPrecision + "m" : "")
			       + ((VerticalPrecision != 10) ? " " + VerticalPrecision + "m" : "");
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 16; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
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
		private static readonly int[] _POWER_OFTEN = new int[] { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

		private static double ConvertPrecision(byte precision)
		{
			int mantissa = ((precision >> 4) & 0x0f) % 10;
			int exponent = (precision & 0x0f) % 10;
			return mantissa * (double) _POWER_OFTEN[exponent] / 100;
		}

		private static byte ConvertPrecision(double precision)
		{
			double centimeters = (precision * 100);

			int exponent;
			for (exponent = 0; exponent < 9; exponent++)
			{
				if (centimeters < _POWER_OFTEN[exponent + 1])
					break;
			}

			int mantissa = (int) (centimeters / _POWER_OFTEN[exponent]);
			if (mantissa > 9)
				mantissa = 9;

			return (byte) ((mantissa << 4) | exponent);
		}
		#endregion

		#region Convert Degree
		private static Degree ConvertDegree(int degrees)
		{
			degrees -= (1 << 31);

			bool isNegative;
			if (degrees < 0)
			{
				isNegative = true;
				degrees = -degrees;
			}
			else
			{
				isNegative = false;
			}

			int milliseconds = degrees % 1000;
			degrees /= 1000;
			int seconds = degrees % 60;
			degrees /= 60;
			int minutes = degrees % 60;
			degrees /= 60;

			return new Degree(isNegative, degrees, minutes, seconds, milliseconds);
		}

		private static int ConvertDegree(Degree degrees)
		{
			int res = degrees.Degrees * 3600000 + degrees.Minutes * 60000 + degrees.Seconds * 1000 + degrees.Milliseconds;

			if (degrees.IsNegative)
				res = -res;

			return res + (1 << 31);
		}
		#endregion

		#region Convert Altitude
		private const int _ALTITUDE_REFERENCE = 10000000;

		private static double ConvertAltitude(int altitude)
		{
			return ((altitude < _ALTITUDE_REFERENCE) ? ((_ALTITUDE_REFERENCE - altitude) * -1) : (altitude - _ALTITUDE_REFERENCE)) / 100d;
		}

		private static int ConvertAltitude(double altitude)
		{
			int centimeter = (int) (altitude * 100);
			return ((centimeter > 0) ? (_ALTITUDE_REFERENCE + centimeter) : (centimeter + _ALTITUDE_REFERENCE));
		}
		#endregion
	}
}