using GostPluginTests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GostPlugin.Tests
{
    [TestClass()]
    public class KuznyechikTests
    {
        /*
         * Reference test vectors
         */

        private readonly byte[] _ref_key = Utils.Unpack("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        private readonly byte[] _ref_plain = Utils.Unpack("1122334455667700FFEEDDCCBBAA9988");
        private readonly byte[] _ref_cipher = Utils.Unpack("7F679D90BEBC24305A468D42B9D4EDCD");

        /*
         * Unit Testss
         */

        [TestMethod()]
        public void Kuznyechik () {
            Kuznyechik chiper = new Kuznyechik();
            chiper.Key = _ref_key;
            CollectionAssert.AreEqual(_ref_cipher, chiper.Encrypt(_ref_plain));
        }

    }
}