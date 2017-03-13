using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt.Common
{
    /// <summary>
    /// Аутентифицированные ключи шифрования.
    /// </summary>
    public class KeyRing
    {
        /// <summary>
        /// Инициализация класса Hasher
        /// </summary>
        protected Hasher hasher = new Hasher();

        // Сгенерированный хэш 512-бит (128 символов)
        // Мы разбиваем это на два 256-битных ключа (64 символа каждый)
        private const int KeyLength = 64;

        /// <summary>
        /// Ключ, используемый шифром.
        /// </summary>
        public string CipherKey { get; set; }

        /// <summary>
        /// Ключ, используемый MAC.
        /// </summary>
        public byte[] MacKey { get; set; }

        /// <summary>
        /// Генерирует хэш SHA-512 из предоставленного пароля и выводит два
        /// 256-битные ключи из хеша.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <returns>A pair of 256-bit keys.</returns>
        public KeyRing Generate(string password)
        {
            // Generate 512-bit hash from password
            var hash = hasher.Sha512(password);

            // Split hash into two 256-bit keys
            return new KeyRing
            {
                CipherKey = hash.Substring(0, KeyLength),
                MacKey = Encoding.UTF8.GetBytes(hash.Substring(KeyLength, KeyLength))
            };
        }
    }
}
