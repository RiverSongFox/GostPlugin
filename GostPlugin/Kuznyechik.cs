using System;
using System.Runtime.InteropServices;

namespace GostPlugin
{
    public class Kuznyechik : ICipherAlgorithm
    {
        private const int BLOCK_SIZE = 16;
        private const int KEY_LENGTH = 32;

        public int BlockSize {
            get {
                return BLOCK_SIZE;
            }
        }

        public byte[] Key {
            set {
                kuz_set_encrypt_key(value);
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

        public Kuznyechik () {
            init_gf256_mul_table();
        }

        /*
         * The following code is based on Markku-Juhani O. Saarinen's <mjos@iki.fi>
         * C implementation of GOST 34.12-2015 algorithm
         * https://github.com/mjosaarinen/kuznechik
         */

        // The S-Box from section 5.1.1

        readonly byte[] _kuz_pi = {
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

        // Linear vector from sect 5.1.2

        readonly byte[] _kuz_lvec = {
            0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
            0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
        };

        /// <summary>
        /// GF(256) multiplication table
        /// </summary>
        byte[][] _gf_mul_256_table = init_gf256_mul_table();

        /// <summary>
        /// Precalculation of GF(256) multiplication table
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Poly multiplication mod p(x) = x^8 + x^7 + x^6 + x + 1
        /// </summary>
        /// <param name="x">1st factor</param>
        /// <param name="y">2nd factor</param>
        /// <returns>Product</returns>
        private static byte kuz_mul_gf256_slow (byte x, byte y) {
            byte z = 0;

            while (y != 0) {
                if ((y & 1) != 0) {
                    z ^= x;
                }

                x = (byte)((x << 1) ^ ((x & 0x80) != 0 ? 0xC3 : 0x00));
                y >>= 1;
            }

            return z;
        }

        [StructLayout(LayoutKind.Explicit)]
        unsafe public struct w128_t
        {
            [FieldOffset(0)]
            public fixed ulong q[2];
            [FieldOffset(0)]
            public fixed byte b[16];
        }

        /// <summary>
        /// Round keys
        /// </summary>
        private w128_t[] _key = new w128_t[10];

        /// <summary>
        /// Key setup routine
        /// </summary>
        /// <param name="value"></param>
        unsafe private void kuz_set_encrypt_key (byte[] key) {
            w128_t c, x, y, z;

            for (int i = 0; i < 16; i++) {
                // This will be have to changed for little-endian systems
                x.b[i] = key[i];
                y.b[i] = key[i + 16];
            }

            _key[0] = x;
            _key[1] = y;

            for (int i = 1; i <= 32; i++) {

                // C Value
                c.q[0] = 0;
                c.q[1] = 0;
                c.b[15] = (byte)i;        // load round in lsb
                kuz_l(ref c);

                z.q[0] = x.q[0] ^ c.q[0];
                z.q[1] = x.q[1] ^ c.q[1];
                for (int j = 0; j < 16; j++)
                    z.b[j] = _kuz_pi[z.b[j]];
                kuz_l(ref z);

                z.q[0] ^= y.q[0];
                z.q[1] ^= y.q[1];

                y.q[0] = x.q[0];
                y.q[1] = x.q[1];

                x.q[0] = z.q[0];
                x.q[1] = z.q[1];

                if ((i & 7) == 0) {
                    _key[(i >> 2)] = x;
                    _key[(i >> 2) + 1] = y;
                }
            }

        }

        /// <summary>
        /// Single-block Encryption routine
        /// </summary>
        /// <param name="data">Plaintext block</param>
        /// <returns>Ciphertext block</returns>
        unsafe public byte[] Encrypt (byte[] data) {
            w128_t x;
            byte[] cipherText = new byte[BLOCK_SIZE];

            x.q[0] = BitConverter.ToUInt64(data, 0);
            x.q[1] = BitConverter.ToUInt64(data, 8);

            for (int i = 0; i < 9; i++) {
                fixed (w128_t* subKey = &_key[i])
                {
                    x.q[0] ^= subKey->q[0];
                    x.q[1] ^= subKey->q[1];
                }

                for (int j = 0; j < 16; j++) {
                    x.b[j] = _kuz_pi[x.b[j]];
                }

                kuz_l(ref x);
            }

            fixed (w128_t* subKey = &_key[9])
            {
                x.q[0] ^= subKey->q[0];
                x.q[1] ^= subKey->q[1];
            }

            Array.Copy(BitConverter.GetBytes(x.q[0]), 0, cipherText, 0, 8);
            Array.Copy(BitConverter.GetBytes(x.q[1]), 0, cipherText, 8, 8);

            return cipherText;
        }

        /// <summary>
        /// Linear operation
        /// </summary>
        /// <param name="w"></param>
        unsafe private void kuz_l (ref w128_t w) {
            byte x;

            fixed (w128_t* wp = &w)
            {
                // 16 rounds
                for (int j = 0; j < 16; j++) {

                    // An LFSR with 16 elements from GF(2^8)
                    x = wp->b[15]; // Since lvec[15] = 1

                    for (int i = 14; i >= 0; i--) {
                        wp->b[i + 1] = wp->b[i];
                        x ^= _gf_mul_256_table[wp->b[i]][_kuz_lvec[i]];
                    }

                    wp->b[0] = x;

                }
            }
        }

    }
}