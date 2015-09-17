using KeePass.Plugins;

namespace GostPlugin
{
    public class GostPluginExt : Plugin
    {
        public override string UpdateUrl { get { return "https://yaruson.github.io/GostPlugin/VersionInformation.txt"; } }

        public override bool Initialize (IPluginHost host) {
            if (host == null || host.CipherPool == null) return false;

            host.CipherPool.AddCipher(new CipherEngine(new Kuznyechik()));
            host.CipherPool.AddCipher(new CipherEngine(new Magma()));

            return true;
        }
    }
}