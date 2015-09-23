using GostPluginTests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GostPlugin.Tests
{
    [TestClass()]
    public class MagmaTests
    {
        /*
         * Reference test vectors
         */

        private readonly byte[] _ref_key = Utils.Unpack("FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        private readonly byte[] _ref_plain = Utils.Unpack("FEDCBA9876543210");
        private readonly byte[] _ref_cipher = Utils.Unpack("4EE901E5C2D8CA3D");

        /*
         * Unit Tests
         */

        [TestMethod()]
        public void Magma () {
            Magma cipher = new Magma();
            cipher.SetKey(_ref_key);
            byte[] result = cipher.Encrypt(_ref_plain);
            CollectionAssert.AreEqual(_ref_cipher, result);
        }

    }
}