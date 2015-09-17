namespace GostPlugin
{
    /// <summary>
    /// Common interface for all ciphers in the plugin.
    /// Allows user to separate cipher algorithm from plugin-related logic.
    /// </summary>
    public interface ICipherAlgorithm
    {
        /// <summary>
        /// Printable cipher name
        /// </summary>
        string Name { get; }
        /// <summary>
        /// Raw cipher UUID
        /// </summary>
        byte[] UuidBytes { get; }
        /// <summary>
        /// Key length in bytes
        /// </summary>
        int KeyLength { get; }
        /// <summary>
        /// Block size in bytes
        /// </summary>
        int BlockSize { get; }
        /// <summary>
        /// Write-only key attribute
        /// </summary>
        byte[] Key { set; }
        /// <summary>
        /// Encrypts block of data using key set before
        /// </summary>
        /// <param name="data">Plain text block</param>
        /// <returns>Cipher text block</returns>
        byte[] Encrypt (byte[] data);
    }
}