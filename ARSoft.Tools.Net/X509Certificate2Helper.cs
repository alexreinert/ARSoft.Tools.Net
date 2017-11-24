using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ARSoft.Tools.Net
{
    public static class X509Certificate2Helper
    {
        //Public domain: No attribution required.

        /// <summary>
        /// Returns the base64 encoded Public Key Pinning hash of the certificate.
        /// </summary>
        /// <param name="Certificate"></param>
        /// <returns>A base-64 encoded string that represents the hash of the certifcate's SubjectPublicKeyInfo</returns>
        public static String GetPublicKeyPinningHash(this X509Certificate2 Certificate, string digest)
        {
            //Get the SubjectPublicKeyInfo member of the certificate
            Byte[] subjectPublicKeyInfo = GetSubjectPublicKeyInfoRaw(Certificate);

            Byte[] hashBytes = null;

            switch (digest.ToUpperInvariant())
            {
                case "SHA256":
                    //Take the SHA2-256 hash of the DER ASN.1 encoded value
                    using (var sha2 = new SHA256Managed())
                    {
                        hashBytes = sha2.ComputeHash(subjectPublicKeyInfo);
                    }
                    break;
            }

            //Convert hash to base64
            String hash = Convert.ToBase64String(hashBytes);

            return hash;
        }

        /// <summary>
        /// Returns the raw ASN.1 DER bytes of the certificate's SubjectPublicKeyInfo section
        /// </summary>
        /// <param name="Certificate"></param>
        /// <returns>A byte array containing ASN.1 DER encoded SubjectPublicKeyInfo</returns>
        public static Byte[] GetSubjectPublicKeyInfoRaw(this X509Certificate2 Certificate)
        {
            //Public domain: No attribution required.
            Byte[] rawCert = Certificate.GetRawCertData();

            /*
             Certificate is, by definition:

                Certificate  ::=  SEQUENCE  {
                    tbsCertificate       TBSCertificate,
                    signatureAlgorithm   AlgorithmIdentifier,
                    signatureValue       BIT STRING  
                }

               TBSCertificate  ::=  SEQUENCE  {
                    version         [0]  EXPLICIT Version DEFAULT v1,
                    serialNumber         CertificateSerialNumber,
                    signature            AlgorithmIdentifier,
                    issuer               Name,
                    validity             Validity,
                    subject              Name,
                    subjectPublicKeyInfo SubjectPublicKeyInfo,
                    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
                    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
                    extensions      [3]  EXPLICIT Extensions       OPTIONAL  -- If present, version MUST be v3
                }

            So we walk to ASN.1 DER tree in order to drill down to the SubjectPublicKeyInfo item
            */
            Byte[] list = AsnNext(ref rawCert, true); //unwrap certificate sequence
            Byte[] tbsCertificate = AsnNext(ref list, false); //get next item; which is tbsCertificate
            list = AsnNext(ref tbsCertificate, true); //unwap tbsCertificate sequence

            Byte[] version = AsnNext(ref list, false); //tbsCertificate.Version
            Byte[] serialNumber = AsnNext(ref list, false); //tbsCertificate.SerialNumber
            Byte[] signature = AsnNext(ref list, false); //tbsCertificate.Signature
            Byte[] issuer = AsnNext(ref list, false); //tbsCertificate.Issuer
            Byte[] validity = AsnNext(ref list, false); //tbsCertificate.Validity
            Byte[] subject = AsnNext(ref list, false); //tbsCertificate.Subject        
            Byte[] subjectPublicKeyInfo = AsnNext(ref list, false); //tbsCertificate.SubjectPublicKeyInfo        

            return subjectPublicKeyInfo;
        }

        static Byte[] AsnNext(ref Byte[] buffer, Boolean unwrap)
        {
            //Public domain: No attribution required.
            Byte[] result;

            if (buffer.Length < 2)
            {
                result = buffer;
                buffer = new Byte[0];
                return result;
            }

            int index = 0;
            Byte entityType = buffer[index];
            index += 1;

            int length = buffer[index];
            index += 1;

            int lengthBytes = 1;
            if (length >= 0x80)
            {
                lengthBytes = length & 0x0F; //low nibble is number of length bytes to follow
                length = 0;

                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) + (int)buffer[2 + i];
                    index += 1;
                }
                lengthBytes++;
            }

            int copyStart;
            int copyLength;
            if (unwrap)
            {
                copyStart = 1 + lengthBytes;
                copyLength = length;
            }
            else
            {
                copyStart = 0;
                copyLength = 1 + lengthBytes + length;
            }
            result = new Byte[copyLength];
            Array.Copy(buffer, copyStart, result, 0, copyLength);

            Byte[] remaining = new Byte[buffer.Length - (copyStart + copyLength)];
            if (remaining.Length > 0)
                Array.Copy(buffer, copyStart + copyLength, remaining, 0, remaining.Length);
            buffer = remaining;

            return result;
        }
    }
}
