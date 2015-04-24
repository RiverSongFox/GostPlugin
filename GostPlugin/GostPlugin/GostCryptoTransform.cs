using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace GostPlugin
{
    public sealed class GostCryptoTransform : ICryptoTransform
    {
        private const int blockSize = 8; // 64-bit
        private const int keyLength = 32; // 256-bit

        private readonly byte[] key = new byte[keyLength];
        private byte[] state = new byte[blockSize];
        private bool encrypt;

        /// <summary>
        /// Creates instance of GOST cipher transform.
        /// </summary>
        /// <param name="key">256-bit key</param>
        /// <param name="state">Initialization vector</param>
        /// <param name="encrypt">Use True for encryption mode</param>
        public GostCryptoTransform(byte[] key, byte[] iv, bool encrypt)
        {
            Array.Copy(key, this.key, keyLength);
            Array.Copy(iv, this.state, blockSize);
            this.encrypt = encrypt;
        }

        /// <summary>
        /// This module implements so-called Cipher Feedback Mode of GOST algorithm which can be
        /// used only to process one set of data - to either encrypt a signle plaintext or decrypt a
        /// single ciphertext.
        /// </summary>
        public bool CanReuseTransform { get { return false; } }

        /// <summary>
        /// This property is always false, because the implementation can handle only 64-bit blocks.
        /// </summary>
        public bool CanTransformMultipleBlocks { get { return false; } }

        /// <summary>
        /// Input block size is always 64-bit.
        /// </summary>
        public int InputBlockSize { get { return blockSize; } }

        /// <summary>
        /// Input block size is always 64-bit.
        /// </summary>
        public int OutputBlockSize { get { return blockSize; } }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputCount == 0) { return inputCount; }
            else { Debug.Assert(inputCount == InputBlockSize, "Input block must be 64-bit long"); }

            byte[] dataBlock = new byte[InputBlockSize];
            Array.Copy(inputBuffer, inputOffset, dataBlock, 0, inputCount);

            byte[] processed = GostECB.Process(state, key, GostECB.SBox_CryptoPro_A, true);
            byte[] result = XOr(dataBlock, processed);

            Array.Copy(result, 0, outputBuffer, outputOffset, inputCount);
            Array.Copy(encrypt ? result : dataBlock, state, blockSize);

            return inputCount;
        }

        private byte[] XOr(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                c[i] = (byte)(a[i] ^ b[i]);
            return c;
        }

        /// <summary>
        /// Processing of the last block does not differ from previous ones, so we can just call
        /// TransformBlock once again.
        /// </summary>
        /// <param name="inputBuffer"></param>
        /// <param name="inputOffset"></param>
        /// <param name="inputCount"></param>
        /// <returns></returns>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] outputBuffer = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
            return outputBuffer;
        }

        public void Dispose()
        {
        }
    }
}