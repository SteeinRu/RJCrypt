using RJCrypt.Common;
using RJCrypt.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt
{
    /// <summary>
    /// AES-реализация шифрования симметричного ключа по структуре Rijndael.
    /// </summary>
    /// 
    /// <code>
    ///     RJCrypt rj = new RJCrypt();
    ///     //Пример шифрования
    ///     string encrypt = rj.Encrypt("Привет","password", RJCrypt.Common.KeySize.Aes256);
    ///     //Пример дешифрования
    ///     string decrypt = rj.Decrypt(encrypt, "password", RJCrypt.Common.KeySize.Aes256);
    /// </code>
    /// 
    /// <list>
    ///     <list type="author">Шамсудин Сердеров</list>
    ///     <list type="copyright">Steein inc 2017</list>
    ///     <list type="version">1.0.0 beta</list>
    /// </list>
    /// 
    public class RJCrypt
    {

        /// <summary>
        /// Инициализация класса Hasher
        /// </summary>
        public Hasher hasher = new Hasher();

        internal const int InitializationVectorSize = 16;
        internal const CipherMode BlockCipherMode = CipherMode.CBC;

        /// <summary>
        /// Шифрует открытый текст, используя шифр Rijndael в режиме CBC с использованием соли HMAC SHA-512 с паролем.
        /// Произвольный 128-битный вектор инициализации генерируется для шифра.
        /// </summary>
        /// <param name="plaintext">Открытый текст для шифрования.</param>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Зашифрованный текст в кодировке Base64.</returns>
        public string Encrypt(string plaintext, string password, KeySize keySize)
        {
            return Encrypt(Encoding.UTF8.GetBytes(plaintext), password, keySize);
        }

        /// <summary>
        /// Шифрует открытый текст, используя шифр Rijndael в режиме CBC с использованием соли HMAC SHA-512 с паролем.
        /// Произвольный 128-битный вектор инициализации генерируется для шифра.
        /// </summary>
        /// <param name="plaintext">Открытый текст для шифрования.</param>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Зашифрованный текст в кодировке Base64.</returns>
        public string Encrypt(byte[] plaintext, string password, KeySize keySize)
        {
            // Генерация случайного IV
            var iv = RandomHash.GenerateRandomBytes(InitializationVectorSize);

            // Шифровать открытый текст
            var ciphertext = Encrypt(plaintext, password, iv, keySize);

            // Кодировать зашифрованный текст
            return Convert.ToBase64String(ciphertext);
        }

        /// <summary>
        /// Шифрует открытый текст, используя шифр Rijndael в режиме CBC с использованием соли HMAC SHA-512 с паролем.
        /// </summary>
        /// <param name="plaintext">Открытый текст для шифрования.</param>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="iv">Вектор инициализации. Должно быть 128 бит.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Зашифрованный.</returns>
        public byte[] Encrypt(byte[] plaintext, string password, byte[] iv, KeySize keySize)
        {
            if (iv.Length != InitializationVectorSize) throw new ArgumentOutOfRangeException(nameof(iv), "Для AES требуется вектор инициализации 128 бит.");

            byte[] ciphertext;
            using (var ms = new MemoryStream())
            {
                // Insert IV at beginning of ciphertext
                ms.Write(iv, 0, iv.Length);

                // Create a CryptoStream to encrypt the plaintext
                using (var cs = new CryptoStream(ms, CreateEncryptor(password, iv, keySize), CryptoStreamMode.Write))
                {
                    // Encrypt the plaintext
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();
                }

                ciphertext = ms.ToArray();
            }

            // IV + Cipher
            return ciphertext;
        }

        /// <summary>
        /// Шифрует файл открытого текста, используя шифр Rijndael в режиме CBC, с помощью соли HMAC SHA-512 с паролем.
        /// Произвольный 128-битный вектор инициализации генерируется для шифра.
        /// </summary>
        /// <param name="plaintextFile">Файл открытого текста для шифрования.</param>
        /// <param name="ciphertextFile">Полученный файл зашифрованного текста.</param>
        /// <param name="password">Пароль для шифрования файла с открытым текстом.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        public void Encrypt(string plaintextFile, string ciphertextFile, string password, KeySize keySize)
        {
            // Создайте новый файл зашифрованного текста, чтобы записать зашифрованный текст в
            using (var fsc = new FileStream(ciphertextFile, FileMode.Create, FileAccess.Write))
            {
                // Сохраните IV в начале файла зашифрованного текста
                var iv = RandomHash.GenerateRandomBytes(InitializationVectorSize);
                fsc.Write(iv, 0, iv.Length);

                // Создать CryptoStream для шифрования открытого текста
                using (var cs = new CryptoStream(fsc, CreateEncryptor(password, iv, keySize), CryptoStreamMode.Write))
                {
                    // Откройте файл открытого текста.
                    using (var fsp = new FileStream(plaintextFile, FileMode.Open, FileAccess.Read))
                    {
                        // Создаем буфер для обработки файла открытого текста в кусках
                        // Чтение целого файла в память может вызвать
                        // исключения из памяти, если файл большой
                        var buffer = new byte[4096];

                        // Чтение фрагмента из файла открытого текста
                        int bytesRead;
                        while ((bytesRead = fsp.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Шифровать открытый текст и записать его в файл зашифрованного текста
                            cs.Write(buffer, 0, bytesRead);
                        }

                        // Завершить шифрование
                        cs.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// Расшифровывает зашифрованный текст, используя шифр Rijndael в режиме CBC с использованием соли HMAC SHA-512 с паролем.
        /// </summary>
        /// <param name="ciphertext">Шифрованный текст в кодировке Base64 для расшифровки.</param>
        /// <param name="password">Пароль для расшифровки зашифрованного текста.</param>
        /// <param name="keySize">Размер ключа шифрования, используемого для создания зашифрованного текста.</param>
        /// <returns>Открытый текст.</returns>
        public string Decrypt(string ciphertext, string password, KeySize keySize)
        {
            return Decrypt(Convert.FromBase64String(ciphertext), password, keySize);
        }

        /// <summary>
        /// Расшифровывает зашифрованный текст, используя шифр Rijndael в режиме CBC с использованием соли HMAC SHA-512 с паролем.
        /// </summary>
        /// <param name="ciphertext">Шифрованный текст для расшифровки.</param>
        /// <param name="password">Пароль для расшифровки зашифрованного текста.</param>
        /// <param name="keySize">Размер ключа шифрования, используемого для создания зашифрованного текста.</param>
        /// <returns>Открытый текст.</returns>
        public string Decrypt(byte[] ciphertext, string password, KeySize keySize)
        {
            using (var ms = new MemoryStream(ciphertext))
            {
                // Extract the IV from the ciphertext
                var iv = new byte[InitializationVectorSize];
                ms.Read(iv, 0, iv.Length);

                // Create a CryptoStream to decrypt the ciphertext
                using (var cs = new CryptoStream(ms, CreateDecryptor(password, iv, keySize), CryptoStreamMode.Read))
                {
                    // Decrypt the ciphertext
                    using (var sr = new StreamReader(cs, Encoding.UTF8)) return sr.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// Расшифровывает зашифрованный текст, используя шифр Rijndael в режиме CBC с использованием соли HMAC SHA-512 с паролем.
        /// </summary>
        /// <param name="ciphertextFile">Файл зашифрованного текста для расшифровки.</param>
        /// <param name="plaintextFile">Получившийся файл открытого текста.</param>
        /// <param name="password">Пароль для дешифрования файла зашифрованного текста.</param>
        /// <param name="keySize">Размер ключа шифрования, используемого для создания файла зашифрованного текста.</param>
        public void Decrypt(string ciphertextFile, string plaintextFile, string password, KeySize keySize)
        {
            // Открыть файл зашифрованного текста
            using (var fsc = new FileStream(ciphertextFile, FileMode.Open, FileAccess.Read))
            {
                // Прочитайте IV от начала файла зашифрованного текста
                var iv = new byte[InitializationVectorSize];
                fsc.Read(iv, 0, iv.Length);

                // Создайте новый файл открытого текста, чтобы записать открытый текст в
                using (var fsp = new FileStream(plaintextFile, FileMode.Create, FileAccess.Write))
                {
                    // Создать CryptoStream для расшифровки зашифрованного текста
                    using (var cs = new CryptoStream(fsp, CreateDecryptor(password, iv, keySize), CryptoStreamMode.Write))
                    {
                        // Создаем буфер для обработки файла открытого текста в кусках
                        // Чтение целого файла в память может вызвать
                        // исключения из памяти, если файл большой
                        var buffer = new byte[4096];

                        // Чтение фрагмента из файла зашифрованного текста
                        int bytesRead;
                        while ((bytesRead = fsc.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Расшифровать зашифрованный текст и записать его в файл открытого текста
                            cs.Write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Сгенерирует криптографический ключ из пароля.
        /// </summary>
        /// <param name="password">Пароль..</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Криптографический ключ.</returns>
        public byte[] GenerateKey(string password, KeySize keySize)
        {
            // Создайте соль, чтобы предотвратить атаки радужных таблиц
            var salt = hasher.Pbkdf2(password, hasher.Sha512(password + password.Length), Settings.HashIterations);

            // Создать ключ из пароля и соли
            return hasher.Pbkdf2(password, salt, Settings.HashIterations, (int)keySize / 8);
        }

        /// <summary>
        /// Создает симметричный шифр Rijndael.
        /// </summary>
        /// <param name="password">Пароль для шифрования открытого текста.</param>
        /// <param name="iv">Вектор инициализации. Должно быть 128 бит.</param>
        /// <param name="keySize">Размер ключа шифрования. 256-бит сильнее, но медленнее.</param>
        /// <returns>Симметричный шифр.</returns>
        public ICryptoTransform CreateEncryptor(string password, byte[] iv, KeySize keySize)
        {
#if NET452
                var rijndael = new RijndaelManaged { Mode = BlockCipherMode };
#else
            var rijndael = Aes.Create();
            rijndael.Mode = BlockCipherMode;
#endif

            return rijndael.CreateEncryptor(GenerateKey(password, keySize), iv);
        }

        /// <summary>
        /// Создает симметричную дешифровку Rijndael.
        /// </summary>
        /// <param name="password">Пароль для расшифровки зашифрованного текста.</param>
        /// <param name="iv">Вектор инициализации. Должно быть 128 бит.</param>
        /// <param name="keySize">Размер ключа шифрования.</param>
        /// <returns>Симметричный дешифратор.</returns>
        public ICryptoTransform CreateDecryptor(string password, byte[] iv, KeySize keySize)
        {
            #if NET452
                var rijndael = new RijndaelManaged { Mode = BlockCipherMode };
            #else
                var rijndael = Aes.Create();
                rijndael.Mode = BlockCipherMode;
            #endif

            return rijndael.CreateDecryptor(GenerateKey(password, keySize), iv);
        }
    }
}
