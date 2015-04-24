using KeePass.Plugins;

namespace GostPlugin
{
    public sealed class GostPluginExt : KeePass.Plugins.Plugin
    {
        private static GostCipherEngine _gostCipher = new GostCipherEngine();

        public override bool Initialize(IPluginHost host)
        {
            if (host != null && _gostCipher != null)
            {
                host.CipherPool.AddCipher(_gostCipher);
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}