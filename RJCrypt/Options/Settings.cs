using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RJCrypt.Options
{
    /// <summary>
    /// Коллекция изменяемых значений по умолчанию
    /// </summary>
    public static class Settings
    {
        static Settings()
        {
            // Устанавливать значения по умолчанию во время инициализации
            Reset();
        }

        /// <summary>
        /// Сбрасывает все настройки на значения по умолчанию.
        /// </summary>
        public static void Reset()
        {
            HashIterations = _hashIterations;
        }

        /// <summary>
        /// Число итераций, используемых для получения хэшей.
        /// По умолчанию 10000.
        /// </summary>
        public static int HashIterations;

        private const int _hashIterations = 10000;
    }
}
