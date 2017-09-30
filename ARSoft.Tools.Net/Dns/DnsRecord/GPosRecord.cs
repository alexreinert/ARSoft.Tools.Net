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
	public class GPosRecord : DnsRecordBase
	{
		public double Longitude { get; private set; }
		public double Latitude { get; private set; }
		public double Altitude { get; private set; }

		internal GPosRecord() {}

		public GPosRecord(string name, int timeToLive, double longitude, double latitude, double altitude)
			: base(name, RecordType.GPos, RecordClass.INet, timeToLive)
		{
			Longitude = longitude;
			Latitude = latitude;
			Altitude = altitude;
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			Longitude = Double.Parse(DnsMessageBase.ParseText(resultData, ref currentPosition), CultureInfo.InvariantCulture);
			Latitude = Double.Parse(DnsMessageBase.ParseText(resultData, ref currentPosition), CultureInfo.InvariantCulture);
			Altitude = Double.Parse(DnsMessageBase.ParseText(resultData, ref currentPosition), CultureInfo.InvariantCulture);
		}

		internal override string RecordDataToString()
		{
			return Longitude.ToString(CultureInfo.InvariantCulture)
			       + " " + Latitude.ToString(CultureInfo.InvariantCulture)
			       + " " + Altitude.ToString(CultureInfo.InvariantCulture);
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 3 + Longitude.ToString().Length + Latitude.ToString().Length + Altitude.ToString().Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeText(messageData, ref currentPosition, Longitude.ToString(CultureInfo.InvariantCulture));
			DnsMessageBase.EncodeText(messageData, ref currentPosition, Latitude.ToString(CultureInfo.InvariantCulture));
			DnsMessageBase.EncodeText(messageData, ref currentPosition, Altitude.ToString(CultureInfo.InvariantCulture));
		}
	}
}