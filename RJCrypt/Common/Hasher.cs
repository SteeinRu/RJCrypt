using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt.Common
{
    /// <summary>
    /// Криптографический хеш-функции.
    /// </summary>
    public class Hasher
    {
        /// <summary>
        /// Генерирует хэш SHA-512 из указанного <paramref name="data"/>.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <returns>Хэш.</returns>
        public string Sha512(string data)
        {
            var hash = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hash).Replace("-", "");
        }

        /// <summary>
        /// Генерирует хэш PBKDF2 из указанного <paramref name="data"/>.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <param name="salt">Соль.</param>
        /// <param name="iterations">Число итераций для получения хеша.</param>
        /// <param name="size">Размер хеша.</param>
        /// <returns>Хэш.</returns>
        public byte[] Pbkdf2(string data, string salt, int iterations, int size = 64)
        {
            return Pbkdf2(data, Encoding.UTF8.GetBytes(salt), iterations, size);
        }

        /// <summary>
        /// Генерирует хэш PBKDF2 из указанного <paramref name="data"/>.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <param name="salt">Соль.</param>
        /// <param name="iterations">Число итераций для получения хеша.</param>
        /// <param name="size">Размер хеша.</param>
        /// <returns>Хэш.</returns>
        public byte[] Pbkdf2(string data, byte[] salt, int iterations, int size = 64)
        {
            return Pbkdf2(Encoding.UTF8.GetBytes(data), salt, iterations, size);
        }

        /// <summary>
        /// Генерирует хэш PBKDF2 из указанного <paramref name="data"/>.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <param name="salt">Соль.</param>
        /// <param name="iterations">Число итераций для получения хеша.</param>
        /// <param name="size">Размер хеша.</param>
        /// <returns>Хэш.</returns>
        internal byte[] Pbkdf2(byte[] data, byte[] salt, int iterations, int size = 64)
        {
            return (new Rfc2898DeriveBytes(data, salt, iterations)).GetBytes(size);
        }
    }
}
