using RJCrypt.Common;
using RJCrypt.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt
{
    /// <summary>
    /// AES-реализация шифрования симметричного ключа Rijndael с использованием
    /// режим Encrypt-MAC для аутентифицированного шифрования.
    /// </summary>
    public sealed class RJEncryptMAC : RJCrypt
    {
        public KeyRing ring = new KeyRing();

        /// <summary>
        /// Шифрует открытый текст, используя режим Encrypt-MAC через шифра Rijndael в
        /// CBC с паролем, полученным из соли HMAC SHA-512. Случайная 128-битная инициализация
        /// Вектор создается для шифра.
        /// </summary>
        /// <param name="plaintext">Открытый текст для шифрования.</param>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Шифрованный текст EncM с кодировкой Base64.</returns>
        public new string Encrypt(string plaintext, string password, KeySize keySize)
        {
            return Encrypt(Encoding.UTF8.GetBytes(plaintext), password, keySize);
        }

        /// <summary>
        /// Шифрует открытый текст, используя режим Encrypt-MAC через шифра Rijndael в
        /// CBC с паролем, полученным из соли HMAC SHA-512. Случайная 128-битная инициализация
        /// Вектор создается для шифра.
        /// </summary>
        /// <param name="plaintext">Открытый текст для шифрования.</param>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Шифрованный текст EncM с кодировкой Base64.</returns>
        public new string Encrypt(byte[] plaintext, string password, KeySize keySize)
        {
            // Генерация случайного IV
            var iv = RandomHash.GenerateRandomBytes(InitializationVectorSize);

            // Шифровать открытый текст
            var etmCiphertext = Encrypt(plaintext, password, iv, keySize);

            // Кодировать зашифрованный текст EtM
            return Convert.ToBase64String(etmCiphertext);
        }

        /// <summary>
        /// Шифрует открытый текст, используя режим Encrypt-MAC через шифра Rijndael в
        /// CBC с паролем, полученным из соли HMAC SHA-512.
        /// </summary>
        /// <param name="plaintext">Открытый текст для шифрования.</param>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="iv">Вектор инициализации. Должно быть 128 бит.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Шифрованный текст.</returns>
        public new byte[] Encrypt(byte[] plaintext, string password, byte[] iv, KeySize keySize)
        {
            // Создание ключей AE
            var keyRing = ring.Generate(password);

            // Шифровать открытый текст
            var ciphertext = Encrypt(plaintext, keyRing.CipherKey, iv, keySize);

            // Вычислить MAC из зашифрованного текста
            var mac = CalculateMac(ciphertext, keyRing.MacKey);

            // Добавить MAC в зашифрованный текст
            var etmCiphertext = new byte[ciphertext.Length + mac.Length];
            Buffer.BlockCopy(ciphertext, 0, etmCiphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(mac, 0, etmCiphertext, ciphertext.Length, mac.Length);

            // IV + Cipher + MAC
            return etmCiphertext;
        }

        /// <summary>
        /// Расшифровывает шифротекст EtM с использованием шифра Rijndael в режиме CBC с паролем
        /// HMAC SHA-512 соль.
        /// </summary>
        /// <param name="etmCiphertext">Шифрованный текст Encrypt-MAC с кодировкой Base64 для расшифровки.</param>
        /// <param name="password">Пароль для дешифрования шифротекста Encrypt-MAC.</param>
        /// <param name="keySize">Размер ключа шифрования, используемого для создания зашифрованного текста Encrypt-MAC.</param>
        /// <returns>Открытый текст.</returns>
        public new string Decrypt(string etmCiphertext, string password, KeySize keySize)
        {
            return Decrypt(Convert.FromBase64String(etmCiphertext), password, keySize);
        }

        /// <summary>
        /// Расшифровывает аутентифицированный зашифрованный текст, используя шифр Rijndael в режиме CBC, используя пароль, полученный
        /// HMAC SHA-512 соль.
        /// </summary>
        /// <param name="etmCiphertext">Шифрованный текст Encrypt-MAC для расшифровки.</param>
        /// <param name="password">Пароль для дешифрования шифротекста Encrypt-MAC.</param>
        /// <param name="keySize">Размер ключа шифрования, используемого для создания зашифрованного текста Encrypt-MAC.</param>
        /// <returns>Открытый текст.</returns>
        public new string Decrypt(byte[] etmCiphertext, string password, KeySize keySize)
        {
            // Создание ключей AE
            var keyRing = ring.Generate(password);

            // Извлечь зашифрованный текст и MAC из зашифрованного текста Encrypt-MAC
            var mac = new byte[keyRing.MacKey.Length];
            var ciphertext = new byte[etmCiphertext.Length - mac.Length];
            using (var ms = new MemoryStream(etmCiphertext))
            {
                // Извлечение зашифрованного текста
                ms.Read(ciphertext, 0, ciphertext.Length);

                //Извлечение MAC
                ms.Read(mac, 0, mac.Length);
            }

            // Вычислить MAC из зашифрованного текста
            var newMac = CalculateMac(ciphertext, keyRing.MacKey);

            // Аутентификация зашифрованного текста
            if (!mac.SequenceEqual(newMac)) throw new Exception("Сбой аутентификации!");

            // Расшифровать зашифрованный текст
            return Decrypt(ciphertext, keyRing.CipherKey, keySize);
        }

        /// <summary>
        /// Вычисляет MAC-адрес для зашифрованного текста.
        /// </summary>
        /// <param name="ciphertext">Шифртекст.</param>
        /// <param name="key">Ключ.</param>
        /// <returns>MAC.</returns>
        public byte[] CalculateMac(byte[] ciphertext, byte[] key)
        {
            return hasher.Pbkdf2(ciphertext, key, Settings.HashIterations);
        }
    }
}
