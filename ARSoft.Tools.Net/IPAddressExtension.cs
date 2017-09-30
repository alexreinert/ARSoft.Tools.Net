using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace ARSoft.Tools.Net
{
	public static class IPAddressExtension
	{
		/// <summary>
		/// Reverses the order of the bytes of an IPAddress
		/// </summary>
		/// <param name="ipAddress">Instance of the IPAddress, that should be reversed</param>
		/// <returns>New instance of IPAddress with reversed address</returns>
		public static IPAddress Reverse(this IPAddress ipAddress)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			byte[] addressBytes = ipAddress.GetAddressBytes();
			byte[] res = new byte[addressBytes.Length];

			for (int i = 0; i < res.Length; i++)
			{
				res[i] = addressBytes[addressBytes.Length - i - 1];
			}

			return new IPAddress(res);
		}

		/// <summary>
		/// Gets the network address for a specified IPAddress and netmask
		/// </summary>
		/// <param name="ipAddress">IPAddress, for that the network address should be returned</param>
		/// <param name="netmask">Netmask, that should be used</param>
		/// <returns>New instance of IPAddress with the network address assigend</returns>
		public static IPAddress GetNetworkAddress(this IPAddress ipAddress, IPAddress netmask)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			if (netmask == null)
				throw new ArgumentNullException("netMask");

			if (ipAddress.AddressFamily != netmask.AddressFamily)
				throw new ArgumentOutOfRangeException("Protocoll version of ipAddress and netmask do not match", "netmask");

			byte[] resultBytes = ipAddress.GetAddressBytes();
			byte[] ipAddressBytes = ipAddress.GetAddressBytes();
			byte[] netmaskBytes = netmask.GetAddressBytes();

			for (int i = 0; i < netmaskBytes.Length; i++)
			{
				resultBytes[i] = (byte)(ipAddressBytes[i] & netmaskBytes[i]);
			}

			return new IPAddress(resultBytes);
		}

		/// <summary>
		/// Gets the network address for a specified IPAddress and netmask
		/// </summary>
		/// <param name="ipAddress">IPAddress, for that the network address should be returned</param>
		/// <param name="netmask">Netmask in CIDR format</param>
		/// <returns>New instance of IPAddress with the network address assigend</returns>
		public static IPAddress GetNetworkAddress(this IPAddress ipAddress, int netmask)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			if ((ipAddress.AddressFamily == AddressFamily.InterNetwork) && ((netmask < 0) || (netmask > 32)))
				throw new ArgumentException("Netmask have to be in range of 0 to 32 on IPv4 addresses", "netmask");

			if ((ipAddress.AddressFamily == AddressFamily.InterNetworkV6) && ((netmask < 0) || (netmask > 128)))
				throw new ArgumentException("Netmask have to be in range of 0 to 128 on IPv6 addresses", "netmask");

			byte[] ipAddressBytes = ipAddress.GetAddressBytes();

			for (int i = 0; i < ipAddressBytes.Length; i++)
			{
				if (netmask >= 8)
				{
					netmask -= 8;
				}
				else
				{
					if (BitConverter.IsLittleEndian)
					{
						ipAddressBytes[i] &= ReverseBitOrder((byte)~(255 << netmask));
					}
					netmask = 0;
				}
			}

			return new IPAddress(ipAddressBytes);
		}

		/// <summary>
		/// Returns the reverse lookup address of an IPAddress
		/// </summary>
		/// <param name="ipAddress">Instance of the IPAddress, that should be used</param>
		/// <returns>A string with the reverse lookup address</returns>
		public static string GetReverseLookupAddress(this IPAddress ipAddress)
		{
			StringBuilder res = new StringBuilder();

			byte[] addressBytes = ipAddress.GetAddressBytes();
			for (int i = addressBytes.Length - 1; i >= 0; i--)
			{
				res.Append(addressBytes[i]);
				res.Append(".");
			}

			if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
			{
				res.Append("in-addr.arpa");
			}
			else
			{
				res.Append("ip6.arpa");
			}

			return res.ToString();
		}

		private static byte ReverseBitOrder(byte value)
		{
			byte result = 0;

			for (int i = 0; i < 8; i++)
			{
				result |= (byte)((((1 << i) & value) >> i) << (7 - i));
			}

			return result;
		}
	}
}
