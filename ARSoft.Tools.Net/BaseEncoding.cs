#region Copyright and License
// Copyright 2010..2022 Alexander Reinert
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

namespace ARSoft.Tools.Net
{
    public static class BaseEncoding
    {
        private static readonly char[] Base16Alphabet = "0123456789ABCDEF".ToCharArray();
        private static readonly Dictionary<char, byte> Base16AlphabetReverseLookup = GetAlphabetReverseLookup(Base16Alphabet, true);

        private static readonly char[] Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
        private static readonly Dictionary<char, byte> Base32AlphabetReverseLookup = GetAlphabetReverseLookup(Base32Alphabet, true);

        private static readonly char[] Base32HexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV".ToCharArray();
        private static readonly Dictionary<char, byte> Base32HexAlphabetReverseLookup = GetAlphabetReverseLookup(Base32HexAlphabet, true);

        private static readonly char[] Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".ToCharArray();
        private static readonly Dictionary<char, byte> Base64AlphabetAlphabetReverseLookup = GetAlphabetReverseLookup(Base64Alphabet, false);

        private static readonly char[] Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".ToCharArray();
        private static readonly Dictionary<char, byte> Base64UrlAlphabetAlphabetReverseLookup = GetAlphabetReverseLookup(Base64UrlAlphabet, false);

        #region Helper
        private static Dictionary<char, byte> GetAlphabetReverseLookup(char[] alphabet, bool isCaseIgnored)
        {
            Dictionary<char, byte> res = new Dictionary<char, byte>(isCaseIgnored ? 2 * alphabet.Length : alphabet.Length);

            for (byte i = 0; i < alphabet.Length; i++)
            {
                res[alphabet[i]] = i;
            }

            if (isCaseIgnored)
            {
                for (byte i = 0; i < alphabet.Length; i++)
                {
                    res[char.ToLowerInvariant(alphabet[i])] = i;
                }
            }

            return res;
        }
        #endregion


        /// <summary>
        ///   Decodes a Base16 string as described in <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inData"> An Base16 encoded string. </param>
        /// <returns> Decoded data </returns>
        public static byte[] FromBase16String(this string inData)
        {
            return Decode(inData, Base16Alphabet, Base16AlphabetReverseLookup);
        }

        /// <summary>
        ///   Converts a byte array to its corresponding Base16 encoding described in
        ///   <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase16String(this byte[] inArray)
        {
            return Encode(inArray, Base16Alphabet);
        }

        /// <summary>
        ///   Decodes a Base32 string as described in <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inData"> An Base32 encoded string. </param>
        /// <returns> Decoded data </returns>
        public static byte[] FromBase32String(this string inData)
        {
            return Decode(inData, Base32Alphabet, Base32AlphabetReverseLookup);
        }

        /// <summary>
        ///   Converts a byte array to its corresponding Base32 encoding described in
        ///   <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase32String(this byte[] inArray)
        {
            return Encode(inArray, Base32Alphabet);
        }

        /// <summary>
        ///   Decodes a Base32Hex string as described in <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inData"> An Base32Hex encoded string. </param>
        /// <returns> Decoded data </returns>
        public static byte[] FromBase32HexString(this string inData)
        {
            return Decode(inData, Base32HexAlphabet, Base32HexAlphabetReverseLookup);
        }

        /// <summary>
        ///   Converts a byte array to its corresponding Base32Hex encoding described in
        ///   <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase32HexString(this byte[] inArray)
        {
            return Encode(inArray, Base32HexAlphabet);
        }

        /// <summary>
        ///   Decodes a Base64 string as described in <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inData"> An Base64 encoded string. </param>
        /// <returns> Decoded data </returns>
        public static byte[] FromBase64String(this string inData)
        {
            return Decode(inData, Base64Alphabet, Base64AlphabetAlphabetReverseLookup);
        }

        /// <summary>
        ///   Converts a byte array to its corresponding Base64 encoding described in
        ///   <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase64String(this byte[] inArray)
        {
            return Encode(inArray, Base64Alphabet);
        }

        /// <summary>
        ///   Decodes a Base64Url string as described in <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inData"> An Base64Url encoded string. </param>
        /// <returns> Decoded data </returns>
        public static byte[] FromBase64UrlString(this string inData)
        {
            return Decode(inData, Base64UrlAlphabet, Base64UrlAlphabetAlphabetReverseLookup);
        }

        /// <summary>
        ///   Converts a byte array to its corresponding Base64Url encoding described in
        ///   <a href="https://www.rfc-editor.org/rfc/rfc4648.html">RFC 4648</a>.
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase64UrlString(this byte[] inArray)
        {
            return Encode(inArray, Base64UrlAlphabet);
        }


        private static byte[] Decode(string input, char[] alphabet, Dictionary<char,byte> reverseAlphabetLookup)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            int bitsPerPlainByte = 8;
            GetBaseEncodingParams(alphabet.Length, out var _, out var bitsPerEncodedByte);

            input = input.TrimEnd('='); // Just remove any padding

            int byteCount = input.Length * bitsPerEncodedByte / bitsPerPlainByte; // Number of bytes after decoding
            byte[] bytes = new byte[byteCount];

            int bitCount = 0;
            int index = 0;
            int value = 0;

            foreach (char c in input)
            {
                int charValue = reverseAlphabetLookup[c];
                value = (value << bitsPerEncodedByte) | charValue;
                bitCount += bitsPerEncodedByte;

                if (bitCount >= bitsPerPlainByte)
                {
                    bytes[index++] = (byte)(value >> (bitCount - bitsPerPlainByte));
                    bitCount -= bitsPerPlainByte;
                }
            }

            return bytes;
        }

        private static string Encode(byte[] bytes, char[] alphabet)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            int bitsPerPlainByte = 8;
            GetBaseEncodingParams(alphabet.Length, out var encodedBlockBytes, out var bitsPerEncodedByte);

            int charCount = (bytes.Length * bitsPerPlainByte / bitsPerEncodedByte) + ((bytes.Length * bitsPerPlainByte % bitsPerEncodedByte) != 0 ? 1 : 0); // divide, ceil
            int paddingCount = (charCount % encodedBlockBytes == 0) ? 0 : (encodedBlockBytes - charCount % encodedBlockBytes);
            char[] chars = new char[charCount + paddingCount];

            int baseMax = alphabet.Length - 1;
            int bitCount = 0;
            int index = 0;
            int value = 0;

            foreach (byte b in bytes)
            {
                value = (value << bitsPerPlainByte) | b;
                bitCount += bitsPerPlainByte;

                while (bitCount >= bitsPerEncodedByte)
                {
                    int charValue = (value >> (bitCount - bitsPerEncodedByte)) & baseMax;
                    chars[index++] = alphabet[charValue];
                    bitCount -= bitsPerEncodedByte;
                }
            }

            if (bitCount > 0)
            {
                int charValue = (value << (bitsPerEncodedByte - bitCount)) & baseMax;
                chars[index++] = alphabet[charValue];
            }

            while (index < charCount + paddingCount)
            {
                chars[index++] = '=';
            }

            return new string(chars);
        }

        private static void GetBaseEncodingParams(int baseEncoding, out int encodedBlockBytes, out int bitsPerEncodedbyte)
        {
            switch (baseEncoding)
            {
                case 16:
                    encodedBlockBytes = 2;
                    bitsPerEncodedbyte = 4;
                    break;
                case 32:
                    encodedBlockBytes = 8;
                    bitsPerEncodedbyte = 5;
                    break;
                case 64:
                    encodedBlockBytes = 4;
                    bitsPerEncodedbyte = 6;
                    break;
                default:
                    throw new ArgumentException("Unsupported base {baseEncoding}", nameof(baseEncoding));
            }
        }
    }
}