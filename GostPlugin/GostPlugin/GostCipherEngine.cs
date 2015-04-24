using KeePassLib;
using KeePassLib.Cryptography.Cipher;
using System.IO;
using System.Security.Cryptography;

namespace GostPlugin
{
    internal class GostCipherEngine : ICipherEngine
    {
        private static readonly byte[] _cipherUuidBytes = new byte[]{
			    0x76, 0xFB, 0x87, 0x6E, 0xA5, 0x26, 0x4C, 0x6A,
                0x9C, 0xFD, 0x52, 0xD1, 0x08, 0x22, 0xA6, 0xF7
        };

        private readonly PwUuid _cipherUuid;

        public GostCipherEngine()
        {
            _cipherUuid = new PwUuid(_cipherUuidBytes);
        }

        public PwUuid CipherUuid { get { return _cipherUuid; } }

        public string DisplayName { get { return "GOST 28147-89 (256-Bit Key)"; } }

        private Stream CreateStream(Stream sInput, bool bEncrypt, byte[] pbKey, byte[] pbIV)
        {
            ICryptoTransform iTransform = new GostCryptoTransform(pbKey, pbIV, bEncrypt);
            return new CryptoStream(sInput, iTransform, bEncrypt ? CryptoStreamMode.Write : CryptoStreamMode.Read);
        }

        public Stream DecryptStream(Stream sEncrypted, byte[] pbKey, byte[] pbIV)
        {
            return CreateStream(sEncrypted, false, pbKey, pbIV);
        }

        public Stream EncryptStream(Stream sPlainText, byte[] pbKey, byte[] pbIV)
        {
            return CreateStream(sPlainText, true, pbKey, pbIV);
        }
    }
}