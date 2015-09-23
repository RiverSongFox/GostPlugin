using KeePassLib;
using KeePassLib.Cryptography.Cipher;
using System.IO;
using System.Security.Cryptography;

namespace GostPlugin
{
    public class CipherEngine : ICipherEngine
    {
        private readonly ICipherAlgorithm _cipher;
        private readonly PwUuid _cipherUUID;

        public CipherEngine (ICipherAlgorithm cipher) {
            _cipher = cipher;
            _cipherUUID = new PwUuid(_cipher.UuidBytes);
        }

        public PwUuid CipherUuid { get { return _cipherUUID; } }
        public string DisplayName { get { return _cipher.Name; } }

        public Stream DecryptStream (Stream sEncrypted, byte[] pbKey, byte[] pbIV) {
            return CreateStream(sEncrypted, false, pbKey, pbIV);
        }

        public Stream EncryptStream (Stream sPlainText, byte[] pbKey, byte[] pbIV) {
            return CreateStream(sPlainText, true, pbKey, pbIV);
        }

        private Stream CreateStream (Stream sInput, bool bEncrypt, byte[] pbKey, byte[] pbIV) {
            ICryptoTransform iTransform = new CFBTransform(pbKey, pbIV, bEncrypt, _cipher);
            return new CryptoStream(sInput, iTransform, bEncrypt ? CryptoStreamMode.Write : CryptoStreamMode.Read);
        }
    }
}