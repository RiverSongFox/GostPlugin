using System;
using System.Linq;

namespace GostPluginTests
{
    static class Utils
    {
        /// <summary>
        /// Decode hexadecimal string into byte array
        /// </summary>
        /// <param name="hex">String</param>
        /// <returns>Byte[]</returns>
        public static byte[] Unpack (string hex) {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
