using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt.Common
{
    /// <summary>
    /// Утвержденные AES размеры ключей шифрования.
    /// </summary>
    public enum KeySize
    {
        /// <summary>
        /// 128-bit
        /// </summary>
        Aes128 = 128,
        /// <summary>
        /// 192-bit
        /// </summary>
        Aes192 = 192,
        /// <summary>
        /// 256-bit
        /// </summary>
        Aes256 = 256
    }
}
