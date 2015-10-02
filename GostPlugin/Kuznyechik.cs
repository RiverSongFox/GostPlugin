using System;

namespace GostPlugin
{
    public class Kuznyechik : ICipherAlgorithm
    {
        private const int BLOCK_SIZE = 16;
        private const int KEY_LENGTH = 32;

        private const int SUB_LENGTH = KEY_LENGTH / 2;

        public int BlockSize {
            get {
                return BLOCK_SIZE;
            }
        }

        public int KeyLength {
            get {
                return KEY_LENGTH;
            }
        }

        public string Name {
            get {
                return "GOST/Kuznyechik (256-Bit Key)";
            }
        }

        public byte[] UuidBytes {
            get {
                return new byte[] { 0x6a, 0x26, 0x1a, 0x17, 0x55, 0x39, 0x41, 0x9d, 0x9d, 0x85, 0x0e, 0x3f, 0x36, 0x31, 0xd0, 0x4b };
            }
        }

        public byte[] Encrypt (byte[] data) {
            byte[] block = new byte[BLOCK_SIZE];
            byte[] temp = new byte[BLOCK_SIZE];

            Array.Copy(data, block, BLOCK_SIZE);

            for (int i = 0; i < 9; i++) {
                LSX(ref temp, ref _subKeys[i], ref block);
                Array.Copy(temp, block, BLOCK_SIZE);
            }

            X(ref block, ref _subKeys[9]);

            return block;

        }

        private byte[][] _subKeys;

        public void SetKey (byte[] key) {

            /*
             * Initialize SubKeys array
             */

            _subKeys = new byte[10][];
            for (int i = 0; i < 10; i++) {
                _subKeys[i] = new byte[SUB_LENGTH];
            }

            byte[] x = new byte[SUB_LENGTH];
            byte[] y = new byte[SUB_LENGTH];

            byte[] c = new byte[SUB_LENGTH];

            /*
             * SubKey[1] = k[255..128]
             * SubKey[2] = k[127..0]
             */

            for (int i = 0; i < SUB_LENGTH; i++) {
                _subKeys[0][i] = x[i] = key[i];
                _subKeys[1][i] = y[i] = key[i + 16];
            }

            for (int k = 1; k < 5; k++) {

                for (int j = 1; j <= 8; j++) {
                    C(ref c, 8 * (k - 1) + j);
                    F(ref c, ref x, ref y);
                }

                Array.Copy(x, _subKeys[2 * k], SUB_LENGTH);
                Array.Copy(y, _subKeys[2 * k + 1], SUB_LENGTH);

            }

        }

        /*
         * Transformations
         */

        private readonly byte[] _pi = {
            0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 	// 00..07
            0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 	// 08..0F
            0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 	// 10..17
            0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1, 	// 18..1F
            0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 	// 20..27
            0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F, 	// 28..2F
            0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 	// 30..37
            0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F, 	// 38..3F
            0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 	// 40..47
            0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC, 	// 48..4F
            0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 	// 50..57
            0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87, 	// 58..5F
            0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 	// 60..67
            0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1, 	// 68..6F
            0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 	// 70..77
            0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57, 	// 78..7F
            0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 	// 80..87
            0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03, 	// 88..8F
            0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 	// 90..97
            0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A, 	// 98..9F
            0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 	// A0..A7
            0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41, 	// A8..AF
            0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 	// B0..B7
            0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B, 	// B8..BF
            0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 	// C0..C7
            0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89, 	// C8..CF
            0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 	// D0..D7
            0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61, 	// D8..DF
            0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 	// E0..E7
            0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52, 	// E8..EF
            0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 	// F0..F7
            0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6, 	// F8..FF
        };

        private readonly byte[] _lFactors = {
            0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
            0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
        };

        private byte[][] _gf_mul = init_gf256_mul_table();

        private static byte[][] init_gf256_mul_table () {
            byte[][] mul_table = new byte[256][];
            for (int x = 0; x < 256; x++) {
                mul_table[x] = new byte[256];
                for (int y = 0; y < 256; y++) {
                    mul_table[x][y] = kuz_mul_gf256_slow((byte)x, (byte)y);
                }
            }
            return mul_table;
        }

        private static byte kuz_mul_gf256_slow (byte a, byte b) {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8 && a != 0 && b != 0; counter++) {
                if ((b & 1) != 0)
                    p ^= a;
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                    a ^= 0xc3; /* x^8 + x^7 + x^6 + x + 1 */
                b >>= 1;
            }
            return p;
        }

        private void S (ref byte[] data) {
            for (int i = 0; i < data.Length; i++) {
                data[i] = _pi[data[i]];
            }
        }

        private void X (ref byte[] result, ref byte[] data) {
            for (int i = 0; i < result.Length; i++) {
                result[i] ^= data[i];
            }
        }

        private byte l (ref byte[] data) {
            byte x = data[15];
            for (int i = 14; i >= 0; i--) {
                x ^= _gf_mul[data[i]][_lFactors[i]];
            }
            return x;
        }

        private void R (ref byte[] data) {
            byte z = l(ref data);
            for (int i = 15; i > 0; i--) {
                data[i] = data[i - 1];
            }
            data[0] = z;
        }

        private void L (ref byte[] data) {
            for (int i = 0; i < 16; i++) {
                R(ref data);
            }
        }

        private void F (ref byte[] k, ref byte[] a1, ref byte[] a0) {
            byte[] temp = new byte[SUB_LENGTH];

            LSX(ref temp, ref k, ref a1);
            X(ref temp, ref a0);

            Array.Copy(a1, a0, SUB_LENGTH);
            Array.Copy(temp, a1, SUB_LENGTH);

        }

        private void LSX (ref byte[] result, ref byte[] k, ref byte[] a) {
            Array.Copy(k, result, BLOCK_SIZE);
            X(ref result, ref a);
            S(ref result);
            L(ref result);
        }

        private void C (ref byte[] c, int i) {
            Array.Clear(c, 0, SUB_LENGTH);
            c[15] = (byte)i;
            L(ref c);
        }

    }
}
