using System;
using System.Diagnostics;

namespace GostPlugin
{
    public class GostECB
    {
        public const int BlockSize = 8; // 64-bit
        public const int KeyLength = 32; // 256-bit

        private readonly byte[][] _sBox = {
            new byte[] { 0x09, 0x06, 0x03, 0x02, 0x08, 0x0b, 0x01, 0x07, 0x0a, 0x04, 0x0e, 0x0f, 0x0c, 0x00, 0x0d, 0x05 },
            new byte[] { 0x03, 0x07, 0x0e, 0x09, 0x08, 0x0a, 0x0f, 0x00, 0x05, 0x02, 0x06, 0x0c, 0x0b, 0x04, 0x0d, 0x01 },
            new byte[] { 0x0e, 0x04, 0x06, 0x02, 0x0b, 0x03, 0x0d, 0x08, 0x0c, 0x0f, 0x05, 0x0a, 0x00, 0x07, 0x01, 0x09 },
            new byte[] { 0x0e, 0x07, 0x0a, 0x0c, 0x0d, 0x01, 0x03, 0x09, 0x00, 0x02, 0x0b, 0x04, 0x0f, 0x08, 0x05, 0x06 },
            new byte[] { 0x0b, 0x05, 0x01, 0x09, 0x08, 0x0d, 0x0f, 0x00, 0x0e, 0x04, 0x02, 0x03, 0x0c, 0x07, 0x0a, 0x06 },
            new byte[] { 0x03, 0x0a, 0x0d, 0x0c, 0x01, 0x02, 0x00, 0x0b, 0x07, 0x05, 0x09, 0x04, 0x08, 0x0f, 0x0e, 0x06 },
            new byte[] { 0x01, 0x0d, 0x02, 0x09, 0x07, 0x0a, 0x06, 0x00, 0x08, 0x0c, 0x04, 0x05, 0x0f, 0x03, 0x0b, 0x0e },
            new byte[] { 0x0b, 0x0a, 0x0f, 0x05, 0x00, 0x0c, 0x0e, 0x08, 0x06, 0x02, 0x03, 0x09, 0x01, 0x07, 0x0d, 0x04 }
        };

        private uint[][] _sBox32;

        public GostECB()
        {
            Convert_sBox();
        }

        private void Convert_sBox()
        {
            _sBox32 = new uint[4][];

            for (int i = 0, j = 0; i < 4; i++, j += 2)
            {
                _sBox32[i] = new uint[256];
                for (int k = 0; k < 256; k++)
                {
                    _sBox32[i][k] = (uint)((_sBox[j][k & 0x0f] ^ _sBox[j + 1][k >> 4] << 4) << (j * 4));
                    _sBox32[i][k] = _sBox32[i][k] << 11 ^ _sBox32[i][k] >> 21;
                }
            }
        }

        public byte[] Process(byte[] data, byte[] key, bool encrypt)
        {
            Debug.Assert(data.Length == BlockSize, "BlockSize must be 64-bit long");
            Debug.Assert(key.Length == KeyLength, "Key must be 256-bit long");

            var a = BitConverter.ToUInt32(data, 0);
            var b = BitConverter.ToUInt32(data, 4);

            var subKeys = GetSubKeys(key);

            var result = new byte[8];

            for (int i = 0; i < 32; i++)
            {
                var keyIndex = GetKeyIndex(i, encrypt);
                var subKey = subKeys[keyIndex];
                var fValue = F(a, subKey, _sBox);
                var round = b ^ fValue;
                if (i < 31)
                {
                    b = a;
                    a = round;
                }
                else
                {
                    b = round;
                }
            }

            Array.Copy(BitConverter.GetBytes(a), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(b), 0, result, 4, 4);

            return result;
        }

        private uint F(uint block, uint subKey, byte[][] _sBox)
        {
            block = (block + subKey) % uint.MaxValue;
            block =
                _sBox32[0][(block & 0x000000ff) >> 0] ^
                _sBox32[1][(block & 0x0000ff00) >> 8] ^
                _sBox32[2][(block & 0x00ff0000) >> 16] ^
                _sBox32[3][(block & 0xff000000) >> 24];
            return block;
        }

        private uint[] GetSubKeys(byte[] key)
        {
            var subKeys = new uint[8];
            for (int i = 0; i < 8; i++)
                subKeys[i] = (uint)BitConverter.ToUInt32(key, i * 4);
            return subKeys;
        }

        private int GetKeyIndex(int i, bool encrypt)
        {
            return encrypt ? (i < 24) ? i % 8 : 7 - (i % 8)
                           : (i < 8) ? i % 8 : 7 - (i % 8);
        }
    }
}