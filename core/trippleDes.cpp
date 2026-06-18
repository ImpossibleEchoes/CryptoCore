#include "pch.h"

#include "trippleDes.h"

#include <iostream>
#include <fstream>
#include <vector>


// =====================================================================
// СТАНДАРТНІ ТАБЛИЦІ DES (Data Encryption Standard)
// =====================================================================
// Усі таблиці взяті з офіційного стандарту FIPS 46-3

// Початкова перестановка (Initial Permutation - IP)
// Біти 64-бітного блоку даних переставляються згідно з цією таблицею
const uint8_t IP[] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

// Кінцева перестановка (Final Permutation - IP^-1)
// Обернена операція до IP, застосовується після 16 раундів Фейстеля
const uint8_t IP_1[] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25
};

// Таблиця розширення (Expansion Permutation - E).
// Розширює 32-бітну праву половину блоку (R) до 48 біт шляхом дублювання деяких бітів.
const uint8_t E[] = {
	32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
	12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
	22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

// Пряма перестановка (Permutation - P).
// Змішує результати, отримані після проходження S-блоків.
const uint8_t P[] = {
	16, 7,  20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8,  24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
};

// Таблиці перестановки ключа (Permuted Choice 1 та 2).
// PC-1: відкидає 8 бітів парності з 64-бітного ключа, роблячи його 56-бітним.
const uint8_t PC1[] = {
	57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39,
	31, 23, 15, 7,  62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37,
	29, 21, 13, 5,  28, 20, 12, 4
};

// PC-2: вибирає 48 бітів з 56-бітного зсунутого ключа для створення раундового підключа.
const uint8_t PC2[] = {
	14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
	26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// Розклад зсувів вліво (Key Shift Schedule) для генерації 16 раундових ключів.
const uint8_t SHIFTS[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// S-блоки (Substitution Boxes - S1...S8).
// Виконують нелінійну заміну: перетворюють 6 біт входу на 4 біти виходу.
const uint8_t SBOX[8][64] = {
	{ // S1
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	{ // S2
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
	{ // S3
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
	{ // S4
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	{ // S5
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	{ // S6
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
	{ // S7
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	{ // S8
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } 
};

// Алгоритм DES

// Універсальна функція перестановки бітів
// Формує нове 64-бітне число, витягуючи біти з вхідного числа (input) згідно з таблицею
uint64_t permute(uint64_t input, const uint8_t* table, int table_size, int input_size) {
	uint64_t result = 0;
	for (int i = 0; i < table_size; ++i) {
		if ((input >> (input_size - table[i])) & 1) {
			result |= (1ULL << (table_size - 1 - i));
		}
	}
	return result;
}

// Генерація 16 раундових ключів (кожен по 48 біт) з одного 64-бітного ключа
void generate_subkeys(uint64_t key, uint64_t subkeys[16]) {

	// Стиснення ключа з 64 до 56 біт (видалення бітів парності)
	uint64_t pc1_key = permute(key, PC1, 56, 64);

	// Розділення на дві половини по 28 біт
	uint32_t C = (pc1_key >> 28) & 0x0FFFFFFF;
	uint32_t D = pc1_key & 0x0FFFFFFF;

	for (int i = 0; i < 16; ++i) {
		// Циклічний зсув вліво обох половин на задану кількість біт (1 або 2)
		C = ((C << SHIFTS[i]) | (C >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
		D = ((D << SHIFTS[i]) | (D >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;

		uint64_t combined = (static_cast<uint64_t>(C) << 28) | D;

		// Фінальна перестановка (PC-2): вибір 48 бітів для поточного раунду
		subkeys[i] = permute(combined, PC2, 48, 56);
	}
}

// Мережа Фейстеля (один повний прохід алгоритму DES для одного блоку даних)
uint64_t des_process(uint64_t block, uint64_t subkeys[16], bool decrypt) {

	// Початкова перестановка
	block = permute(block, IP, 64, 64);

	// Розбиття 64-бітного блоку на дві 32-бітні половини
	uint32_t L = (block >> 32) & 0xFFFFFFFF;
	uint32_t R = block & 0xFFFFFFFF;

	// Виконання 16 раундів
	for (int i = 0; i < 16; ++i) {
		// При дешифруванні раундові ключі застосовуються у зворотному порядку
		uint64_t round_key = decrypt ? subkeys[15 - i] : subkeys[i];

		// Функція F: Розширення правої половини з 32 до 48 біт
		uint64_t expanded_R = permute(R, E, 48, 32);

		// Накладання раундового ключа (XOR)
		uint64_t xor_res = expanded_R ^ round_key;

		// Підстановка через S-блоки (стиснення 48 біт назад у 32 біти)
		uint32_t sbox_res = 0;
		for (int j = 0; j < 8; ++j) {
			uint8_t chunk = (xor_res >> (42 - 6 * j)) & 0x3F; // Беремо блок з 6 біт
			uint8_t row = ((chunk & 0x20) >> 4) | (chunk & 0x01); // 1-й та 6-й біти визначають рядок
			uint8_t col = (chunk >> 1) & 0x0F; // Середні 4 біти визначають колонку
			sbox_res = (sbox_res << 4) | SBOX[j][row * 16 + col];
		}

		// Пряма перестановка P
		uint32_t f_res = static_cast<uint32_t>(permute(sbox_res, P, 32, 32));

		// Обмін
		uint32_t new_R = L ^ f_res;
		L = R;
		R = new_R;
	}

	uint64_t combined = (static_cast<uint64_t>(R) << 32) | L; // Обмін останніх L і R

	// Кінцева перестановка
	return permute(combined, IP_1, 64, 64);
}

// 3DES: Шифрування = Encrypt(K1) -> Decrypt(K2) -> Encrypt(K3)
uint64_t des3_encrypt(uint64_t block, uint64_t sk1[16], uint64_t sk2[16], uint64_t sk3[16]) {
	block = des_process(block, sk1, false);
	block = des_process(block, sk2, true);
	return des_process(block, sk3, false);
}

// 3DES: Дешифрування = Decrypt(K3) -> Encrypt(K2) -> Decrypt(K1)
uint64_t des3_decrypt(uint64_t block, uint64_t sk1[16], uint64_t sk2[16], uint64_t sk3[16]) {
	block = des_process(block, sk3, true);
	block = des_process(block, sk2, false);
	return des_process(block, sk1, true);
}


// =====================================================================
// 
// =====================================================================


// key_24_bytes - ключ 3DES длиной 192 бита (24 байта)
int process_file_3des_internal(const char* in_path,  const char* out_path, const uint8_t* key_24_bytes, int is_encrypt, ProgressCallback callback) {
	std::ifstream fin(in_path, std::ios::binary);
	if (!fin.is_open()) return -1;

	std::ofstream fout(out_path, std::ios::binary);
	if (!fout.is_open()) return -1;

	// Розбиття 24-байтного майстер-ключа на три 8-байтні ключі (K1, K2, K3)
	uint64_t K1 = 0, K2 = 0, K3 = 0;
	for (int i = 0; i < 8; ++i) {
		K1 = (K1 << 8) | key_24_bytes[i];
		K2 = (K2 << 8) | key_24_bytes[i + 8];
		K3 = (K3 << 8) | key_24_bytes[i + 16];
	}

	// Генерація раундових ключів для кожного з трьох ключів
	uint64_t sk1[16], sk2[16], sk3[16];
	generate_subkeys(K1, sk1);
	generate_subkeys(K2, sk2);
	generate_subkeys(K3, sk3);

	// Получаем размер файла
	fin.seekg(0, std::ios::end);
	long long file_size = fin.tellg();
	fin.seekg(0, std::ios::beg);
	long long processed = 0;
	int last_percent = -1;

	uint64_t iv = 0; // Вектор ініціалізації для CBC

	if (is_encrypt) {
		while (fin) {
			uint8_t buffer[8] = { 0 };
			fin.read(reinterpret_cast<char*>(buffer), 8);
			int bytes_read = static_cast<int>(fin.gcount());

			// СТАНДАРТ ДОПОВНЕННЯ (Padding) PKCS#7 (Розмір блоку - 8 байт)
			if (bytes_read == 0) {
				// Якщо файл ідеально кратний 8 байтам, додаємо 
				// повністю новий блок, заповнений числом 8 (0x08)
				for (int j = 0; j < 8; ++j) buffer[j] = 0x08;
				bytes_read = 8;
			}
			else if (bytes_read < 8) {
				// Якщо не вистачає кількох байтів, заповнюємо їх числом, яке дорівнює їх кількості
				uint8_t pad_val = 8 - bytes_read;
				for (int j = bytes_read; j < 8; ++j) buffer[j] = pad_val;
				bytes_read = 8;
			}

			// Перетворення масиву байтів у 64-бітне число (Big Endian)
			uint64_t block = 0;
			for (int i = 0; i < 8; ++i) block = (block << 8) | buffer[i];

			block ^= iv; // CBC XOR

			// Застосування каскаду 3DES
			block = des3_encrypt(block, sk1, sk2, sk3);
			iv = block; // Оновлення IV

			// Запис результату
			for (int i = 7; i >= 0; --i) buffer[i] = (block >> ((7 - i) * 8)) & 0xFF;
			fout.write(reinterpret_cast<char*>(buffer), 8);

			processed += fin.gcount();
			int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
			if (percent != last_percent && callback) { callback(percent); last_percent = percent; }

			if (fin.eof()) break; // Если мы обработали паддинг
		}
	}
	else { // Дешифровка
		uint64_t prev_iv = iv;

		while (fin) {
			uint8_t buffer[8] = { 0 };
			fin.read(reinterpret_cast<char*>(buffer), 8);
			if (fin.gcount() == 0) break;

			uint64_t current_cipher = 0;
			for (int i = 0; i < 8; ++i) current_cipher = (current_cipher << 8) | buffer[i];

			// Застосування зворотного каскаду 3DES
			uint64_t block = des3_decrypt(current_cipher, sk1, sk2, sk3);

			block ^= prev_iv; // CBC XOR
			prev_iv = current_cipher;

			for (int i = 7; i >= 0; --i) buffer[i] = (block >> ((7 - i) * 8)) & 0xFF;

			// ЗНЯТТЯ ДОПОВНЕННЯ (Unpadding) PKCS#7
			// Виконується тільки для останнього блоку файлу
			if (fin.peek() == EOF) {
				// В PKCS#7 останній байт завжди містить кількість доданих байтів
				uint8_t pad_val = buffer[7];
				int valid_bytes = 8;

				// Перевірка цілісності: значення паддінгу для 3DES має бути від 1 до 8
				if (pad_val > 0 && pad_val <= 8) {
					valid_bytes = 8 - pad_val;
				}

				// Записуємо тільки корисні дані (відкидаємо байти доповнення)
				fout.write(reinterpret_cast<char*>(buffer), valid_bytes);
			}
			else {
				// Якщо це не останній блок - записуємо всі 8 байт
				fout.write(reinterpret_cast<char*>(buffer), 8);
			}

			processed += 8;
			int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
			if (percent != last_percent && callback) { callback(percent); last_percent = percent; }
		}
	}

	// Очищення раундових ключів 3DES
	secure_memory_scrub(sk1, sizeof(sk1));
	secure_memory_scrub(sk2, sizeof(sk2));
	secure_memory_scrub(sk3, sizeof(sk3));
	return 0;
}

// Внутрішня функція для застарілого (одинарного) алгоритму DES
// У системі залишена виключно для забезпечення зворотної сумісності
int process_file_des_internal(const char* in_path, const char* out_path, const uint8_t* key_8_bytes, int is_encrypt, ProgressCallback callback) {
	std::ifstream fin(in_path, std::ios::binary);
	if (!fin.is_open()) return -1;

	std::ofstream fout(out_path, std::ios::binary);
	if (!fout.is_open()) return -1;

	// Для класичного DES використовується лише один 64-бітний (ефективних 56) ключ
	uint64_t K1 = 0;
	for (int i = 0; i < 8; ++i) {
		K1 = (K1 << 8) | key_8_bytes[i];
	}

	uint64_t sk1[16];
	generate_subkeys(K1, sk1); // Генерируем 16 раундових ключів

	// Получаем размер файла
	fin.seekg(0, std::ios::end);
	long long file_size = fin.tellg();
	fin.seekg(0, std::ios::beg);
	long long processed = 0;
	int last_percent = -1;

	uint64_t iv = 0; // Вектор ініціалізації для CBC

	if (is_encrypt) {
		while (fin) {
			uint8_t buffer[8] = { 0 };
			fin.read(reinterpret_cast<char*>(buffer), 8);
			int bytes_read = static_cast<int>(fin.gcount());

			// СТАНДАРТ ДОПОВНЕННЯ (Padding) PKCS#7 (Розмір блоку - 8 байт)
			if (bytes_read == 0) {
				// Якщо розмір файлу ідеально кратний 8, стандарт вимагає додати 
				// один повністю новий блок, заповнений числом 8 (0x08)
				for (int j = 0; j < 8; ++j) buffer[j] = 0x08;
				bytes_read = 8;
			}
			else if (bytes_read < 8) {
				// Якщо не вистачає кількох байтів, заповнюємо їх числом, яке дорівнює їх кількості
				uint8_t pad_val = 8 - bytes_read;
				for (int j = bytes_read; j < 8; ++j) buffer[j] = pad_val;
				bytes_read = 8;
			}

			uint64_t block = 0;
			for (int i = 0; i < 8; ++i) block = (block << 8) | buffer[i];

			block ^= iv; // CBC XOR

			// Виклик базової функції Фейстеля для одного проходу
			block = des_process(block, sk1, false);

			iv = block;

			for (int i = 7; i >= 0; --i) buffer[i] = (block >> ((7 - i) * 8)) & 0xFF;
			fout.write(reinterpret_cast<char*>(buffer), 8);

			processed += fin.gcount();
			int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
			if (percent != last_percent && callback) { callback(percent); last_percent = percent; }

			if (fin.eof()) break;
		}
	}
	else { // Дешифровка
		uint64_t prev_iv = iv;

		while (fin) {
			uint8_t buffer[8] = { 0 };
			fin.read(reinterpret_cast<char*>(buffer), 8);
			if (fin.gcount() == 0) break;

			uint64_t current_cipher = 0;
			for (int i = 0; i < 8; ++i) current_cipher = (current_cipher << 8) | buffer[i];

			// Дешифрування класичним DES
			uint64_t block = des_process(current_cipher, sk1, true);

			block ^= prev_iv; // CBC XOR
			prev_iv = current_cipher;

			for (int i = 7; i >= 0; --i) buffer[i] = (block >> ((7 - i) * 8)) & 0xFF;

			// ЗНЯТТЯ ДОПОВНЕННЯ (Unpadding) PKCS#7
			// Виконується тільки для останнього блоку файлу
			if (fin.peek() == EOF) {
				// В PKCS#7 останній байт завжди містить кількість доданих байтів
				uint8_t pad_val = buffer[7];
				int valid_bytes = 8;

				// Перевірка цілісності: значення паддінгу для DES має бути від 1 до 8
				if (pad_val > 0 && pad_val <= 8) {
					valid_bytes = 8 - pad_val;
				}

				// Записуємо тільки корисні дані (відкидаємо байти доповнення)
				fout.write(reinterpret_cast<char*>(buffer), valid_bytes);
			}
			else {
				// Якщо це не останній блок - записуємо всі 8 байт
				fout.write(reinterpret_cast<char*>(buffer), 8);
			}

			processed += 8;
			int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
			if (percent != last_percent && callback) { callback(percent); last_percent = percent; }
		}
	}

	// Очищення раундових ключів DES
	secure_memory_scrub(sk1, sizeof(sk1));
	return 0;
}

