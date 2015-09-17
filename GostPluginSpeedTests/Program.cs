using GostPlugin;
using System;
using System.Diagnostics;
using System.IO;

namespace GostPluginSpeedTests
{
    class Program
    {
        static void Main (string[] args) {
            KuznyechikSpeedTest();
            MagmaSpeedTest();
            //Console.ReadLine();
        }

        static void KuznyechikSpeedTest() {
            Console.WriteLine(SpeedTest(new Kuznyechik()));
        }

        static void MagmaSpeedTest () {
            Console.WriteLine(SpeedTest(new Magma()));
        }

        /// <summary>
        /// Measure cipher performance in MB/s
        /// </summary>
        /// <param name="cipher">Cipher instance</param>
        /// <returns>Speed in MB/s</returns>
        public static string SpeedTest (ICipherAlgorithm cipher) {
            const int SAMPLE_SIZE_KB = 4;
            const int TEST_CYCLES = 1024;

            byte[] plainText = new byte[SAMPLE_SIZE_KB * 1024];
            byte[] key = new byte[cipher.KeyLength];
            byte[] iv = new byte[cipher.BlockSize];

            Random rng = new Random();
            rng.NextBytes(plainText);
            rng.NextBytes(key);
            rng.NextBytes(iv);

            CipherEngine engine = new CipherEngine(cipher);
            Stream cipherStream = engine.EncryptStream(new MemoryStream(), key, iv);

            Stopwatch sw = new Stopwatch();

            sw.Start();
            for (int c = 0; c < TEST_CYCLES; c++) {
                using (MemoryStream plainTextStream = new MemoryStream(plainText)) {
                    plainTextStream.WriteTo(cipherStream);
                }
            }
            sw.Stop();

            return String.Format("{0} = {1:0.00} KB/s", cipher.Name, (float)((1000.0 * SAMPLE_SIZE_KB * TEST_CYCLES) / (sw.ElapsedMilliseconds * 1.0)));
        }

    }
}
