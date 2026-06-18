// core.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "core.h"
#include "trippleDes.h"
#include "blowfish.h"
#include "aes256.h"

#include <immintrin.h>

#include <string>
#include <fstream>
#include <iostream>

// extern "C" забороняє компілятору C++ змінювати імена функцій (Name Mangling)
// Це критично важливо, щоб інтерпретатор Python міг знайти цю функцію у DLL за її точним іменем
extern "C" {

	// __declspec(dllexport) вказує Windows, що цю функцію потрібно експортувати у публічну таблицю DLL, щоб її могли викликати інші програми.
	__declspec(dllexport) int process_file(
		const char* in_path,
		const char* out_path,
		const char* algo,
		const uint8_t* key,
		int is_encrypt,
		ProgressCallback callback)
	{
		std::string algo_str(algo);


		// Відкриваємо файл на самому початку, щоб у разі помилки доступу негайно повернути код помилки (-1) і уникнути створення порожнього вихідного файлу
		std::ifstream fin(in_path, std::ios::binary);
		if (!fin.is_open()) {
			return -1;
		}

		std::ofstream fout(out_path, std::ios::binary);
		if (!fout.is_open()) {
			return -1;
		}

		// Визначення розміру файлу для коректного розрахунку відсотків прогрес-бару
		fin.seekg(0, std::ios::end);
		long long file_size = fin.tellg();
		fin.seekg(0, std::ios::beg);

		if (algo_str == "SSE_XOR") {

			// Альтернативний високошвидкісний алгоритм для некритичних даних
			// Використовує векторні інструкції процесора (SIMD) для паралельної обробки
			const int CHUNK_SIZE = 4096 * 1024; // 4 МБ буфер

			// Виділяємо пам'ять у купі (Heap), щоб не переповнити стек великими масивами
			uint8_t* in_buf = new uint8_t[CHUNK_SIZE];

			long long processed = 0;
			int last_percent = -1;

			// Завантажуємо 16 байт (128 біт) ключа безпосередньо у спеціальний XMM регістр процесора
			__m128i v_key = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
			while (fin) {
				fin.read(reinterpret_cast<char*>(in_buf), CHUNK_SIZE);
				int bytes_read = static_cast<int>(fin.gcount());
				if (bytes_read == 0) break;

				int i = 0;

				// Векторизований цикл обробки: беремо одразу по 16 байт за одну ітерацію
				for (; i + 15 < bytes_read; i += 16) {

					// Завантажуємо 16 байт даних з пам'яті у процесор
					__m128i v_data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&in_buf[i]));

					// Апаратна операція XOR на рівні 128-бітного регістра (виконується за 1 такт)
					v_data = _mm_xor_si128(v_data, v_key);

					// Вивантажуємо результат назад у буфер
					_mm_storeu_si128(reinterpret_cast<__m128i*>(&in_buf[i]), v_data);
				}

				// Хвіст. Обробка останніх байтів (якщо розмір файлу не кратний 16)
				// Виконується звичайним скалярним циклом
				for (; i < bytes_read; ++i) in_buf[i] ^= key[i % 16];

				// Запис зашифрованого/розшифрованого чанка у файл
				fout.write(reinterpret_cast<char*>(in_buf), bytes_read);

				processed += bytes_read;
				int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
				if (percent != last_percent && callback) {
					callback(percent);
					last_percent = percent;
				}
			}

			secure_memory_scrub(in_buf, CHUNK_SIZE);

			// Звільнення пам'яті
			delete[] in_buf;
		}

		// Блокові шифри
		else if (algo_str == "des-ede3-cbc") {
			return process_file_3des_internal(in_path, out_path, key, is_encrypt, callback);
		}
		else if (algo_str == "des-cbc") {
			return process_file_des_internal(in_path, out_path, key, is_encrypt, callback);
		}
		else if (algo_str == "blowfish-cbc") {
			return process_file_blowfish_internal(in_path, out_path, key, 32, is_encrypt, callback);
		}
		else if (algo_str == "aes-256-cbc") {
			return process_file_aes256_internal(in_path, out_path, key, is_encrypt, callback);
		}


		return 0; // Успіх
	}
}