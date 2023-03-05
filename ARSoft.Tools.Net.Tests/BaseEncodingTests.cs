using System.Text;
using Xunit;

namespace ARSoft.Tools.Net.Tests
{
    public class RFC4648_Test_Vectors_Base16
    {
        // Test vectors taken from RFC4648
        // https://www.rfc-editor.org/rfc/rfc4648#section-10

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "66")]
        [InlineData("fo", "666F")]
        [InlineData("foo", "666F6F")]
        [InlineData("foob", "666F6F62")]
        [InlineData("fooba", "666F6F6261")]
        [InlineData("foobar", "666F6F626172")]
        public void Base16_TestVectors_Encode(string plain, string baseEncoded)
        {
            var inputBytes = Encoding.ASCII.GetBytes(plain);
            var encoded = inputBytes.ToBase16String();

            Assert.Equal(baseEncoded, encoded);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "66")]
        [InlineData("fo", "666F")]
        [InlineData("foo", "666F6F")]
        [InlineData("foob", "666F6F62")]
        [InlineData("fooba", "666F6F6261")]
        [InlineData("foobar", "666F6F626172")]
        public void Base16_TestVectors_Decode(string plain, string baseEncoded)
        {
            var outputBytes = baseEncoded.FromBase16String();
            var decoded = Encoding.ASCII.GetString(outputBytes);

            Assert.Equal(plain, decoded);
        }
    }

    public class RFC4648_Test_Vectors_Base32
    {
        // Test vectors taken from RFC4648
        // https://www.rfc-editor.org/rfc/rfc4648#section-10

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public void Base32_TestVectors_Encode(string plain, string baseEncoded)
        {
            var inputBytes = Encoding.ASCII.GetBytes(plain);
            var encoded = inputBytes.ToBase32String();

            Assert.Equal(baseEncoded, encoded);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public void Base32_TestVectors_Decode(string plain, string baseEncoded)
        {
            var outputBytes = baseEncoded.FromBase32String();
            var decoded = Encoding.ASCII.GetString(outputBytes);

            Assert.Equal(plain, decoded);
        }
    }

    public class RFC4648_Test_Vectors_Base32Hex
    {
        // Test vectors taken from RFC4648
        // https://www.rfc-editor.org/rfc/rfc4648#section-10

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "CO======")]
        [InlineData("fo", "CPNG====")]
        [InlineData("foo", "CPNMU===")]
        [InlineData("foob", "CPNMUOG=")]
        [InlineData("fooba", "CPNMUOJ1")]
        [InlineData("foobar", "CPNMUOJ1E8======")]
        public void Base32Hex_TestVectors_Encode(string plain, string baseEncoded)
        {
            var inputBytes = Encoding.ASCII.GetBytes(plain);
            var encoded = inputBytes.ToBase32HexString();

            Assert.Equal(baseEncoded, encoded);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "CO======")]
        [InlineData("fo", "CPNG====")]
        [InlineData("foo", "CPNMU===")]
        [InlineData("foob", "CPNMUOG=")]
        [InlineData("fooba", "CPNMUOJ1")]
        [InlineData("foobar", "CPNMUOJ1E8======")]
        public void Base32Hex_TestVectors_Decode(string plain, string baseEncoded)
        {
            var outputBytes = baseEncoded.FromBase32HexString();
            var decoded = Encoding.ASCII.GetString(outputBytes);

            Assert.Equal(plain, decoded);
        }
    }


    public class RFC4648_Test_Vectors_Base64
    {
        // Test vectors taken from RFC4648
        // https://www.rfc-editor.org/rfc/rfc4648#section-10

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        public void Base64_TestVectors_Encode(string plain, string baseEncoded)
        {
            var inputBytes = Encoding.ASCII.GetBytes(plain);
            var encoded = inputBytes.ToBase64String();

            Assert.Equal(baseEncoded, encoded);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        public void Base64_TestVectors_Decode(string plain, string baseEncoded)
        {
            var outputBytes = baseEncoded.FromBase64String();
            var decoded = Encoding.ASCII.GetString(outputBytes);

            Assert.Equal(plain, decoded);
        }
    }

    public class RFC4648_Test_Vectors_Base64Url
    {
        // Test vectors taken from RFC4648
        // https://www.rfc-editor.org/rfc/rfc4648#section-10

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        public void Base64Url_TestVectors_Encode(string plain, string baseEncoded)
        {
            var inputBytes = Encoding.ASCII.GetBytes(plain);
            var encoded = inputBytes.ToBase64UrlString();

            Assert.Equal(baseEncoded, encoded);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        public void Base64Url_TestVectors_Decode(string plain, string baseEncoded)
        {
            var outputBytes = baseEncoded.FromBase64UrlString();
            var decoded = Encoding.ASCII.GetString(outputBytes);

            Assert.Equal(plain, decoded);
        }
    }


    public class BaseEncodingRegressionTests
    {
        [Fact]
        public void Base32Hex_Example_That_Used_to_Get_Corrupted()
        {
            var input = "NI9BSNE6JGFGO330HU4KGSP09POHFG62";

            var asBytes = input.FromBase32HexString();
            var encodedString = asBytes.ToBase32HexString();

            Assert.Equal(input, encodedString);
        }
    }
}
