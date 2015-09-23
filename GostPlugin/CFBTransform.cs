using System;
using System.Security.Cryptography;

namespace GostPlugin
{
    internal class CFBTransform : ICryptoTransform
    {
        private readonly ICipherAlgorithm _cipher;
        private readonly bool _encrypt;
        private readonly byte[] _state;

        public CFBTransform (byte[] pbKey, byte[] pbIV, bool bEncrypt, ICipherAlgorithm cipher) {
            _cipher = cipher;
            _cipher.SetKey(pbKey);

            _encrypt = bEncrypt;

            _state = new byte[_cipher.BlockSize];
            Array.Copy(pbIV, _state, _cipher.BlockSize);
        }

        public bool CanReuseTransform { get { return false; } }
        public bool CanTransformMultipleBlocks { get { return false; } }
        public int InputBlockSize { get { return _cipher.BlockSize; } }
        public int OutputBlockSize { get { return _cipher.BlockSize; } }

        public int TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset) {
            if (inputCount == 0) return inputCount;

            byte[] dataBlock = new byte[inputCount];
            byte[] result = new byte[inputCount];

            Array.Copy(inputBuffer, inputOffset, dataBlock, 0, inputCount);

            byte[] gamma = _cipher.Encrypt(_state);

            for (int i = 0; i < dataBlock.Length; i++) {
                result[i] = (byte)(dataBlock[i] ^ gamma[i]);
            }

            Array.Copy(result, 0, outputBuffer, outputOffset, inputCount);
            Array.Copy(_encrypt ? result : dataBlock, _state, inputCount);

            return inputCount;
        }

        public byte[] TransformFinalBlock (byte[] inputBuffer, int inputOffset, int inputCount) {
            byte[] outputBuffer = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
            return outputBuffer;
        }

        public void Dispose () {
        }
    }
}