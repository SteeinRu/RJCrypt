using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt.Options
{
    public static class RandomHash
    {
        private static readonly RandomNumberGenerator Random;

        /// <summary>
        /// Конструктор
        /// </summary>
        static RandomHash()
        {
            Random = RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Создает массив байтов с использованием криптографически сильной последовательности
        /// случайных значений.
        /// </summary>
        /// <param name="size">Размер массива.</param>
        /// <returns>Массив байтов.</returns>
        public static byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            Random.GetBytes(bytes);
            return bytes;
        }
    }
}
