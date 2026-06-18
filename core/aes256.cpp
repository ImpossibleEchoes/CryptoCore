#include "pch.h"

#include "aes256.h"

#include <cstdint>
#include <iostream>
#include <fstream>

// =====================================================================
// СТАНДАРТНІ ТАБЛИЦІ AES-256 (Згідно зі специфікацією FIPS 197)
// =====================================================================

// S-box (Substitution box) - таблиця для нелінійної заміни байтів під час шифрування
const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box - зворотна таблиця для дешифрування
const uint8_t rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon (Round Constants) - константи для генерації раундових ключів
const uint8_t rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
};

// Контекст алгоритму AES-256. 
// Зберігає розширений ключ розміром 240 байт (15 ключів по 16 байт для 14 раундів + 1 початковий)
struct Aes256Ctx {
	uint8_t RoundKey[240];
};

// =====================================================================
// ЯДРО АЛГОРИТМУ AES-256 (Математичний апарат)
// =====================================================================

// Макрос для множення на 2 у скінченному полі Галуа GF(2^8)
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

// Функція Key Expansion: розширює 32-байтний ключ користувача до 240 байт раундових ключів
void aes256_init(Aes256Ctx* ctx, const uint8_t* key) {
	unsigned i, j, k;
	uint8_t tempa[4];

	// Крок 1: Копіюємо оригінальний 32-байтний ключ у початок масиву раундових ключів
	for (i = 0; i < 32; ++i) ctx->RoundKey[i] = key[i];

	// Крок 2: Генерація наступних раундових ключів (Key Schedule)
	for (i = 32; i < 240; i += 4) {
		for (j = 0; j < 4; ++j) tempa[j] = ctx->RoundKey[i - 4 + j];

		if (i % 32 == 0) {
			k = tempa[0];
			tempa[0] = sbox[tempa[1]] ^ rcon[i / 32];
			tempa[1] = sbox[tempa[2]];
			tempa[2] = sbox[tempa[3]];
			tempa[3] = sbox[k];
		}

		// Специфічний крок ТІЛЬКИ для AES-256 (додаткова нелінійна заміна)
		else if (i % 32 == 16) {
			for (j = 0; j < 4; ++j) tempa[j] = sbox[tempa[j]];
		}

		for (j = 0; j < 4; ++j) ctx->RoundKey[i + j] = ctx->RoundKey[i - 32 + j] ^ tempa[j];
	}
}

// AddRoundKey: Операція XOR (виключне АБО) між поточним станом блоку та раундовим ключем
void aes_addRoundKey(uint8_t round, uint8_t* state, const uint8_t* RoundKey) {
	for (int i = 0; i < 16; ++i) state[i] ^= RoundKey[(round * 16) + i];
}

// SubBytes: Побайтова нелінійна заміна з використанням таблиці S-box
void aes_subBytes(uint8_t* state) {
	for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

// InvSubBytes: Зворотна заміна для дешифрування
void aes_invSubBytes(uint8_t* state) {
	for (int i = 0; i < 16; ++i) state[i] = rsbox[state[i]];
}

// ShiftRows: Циклічний зсув рядків матриці стану (забезпечує дифузію)
void aes_shiftRows(uint8_t* state) {
	uint8_t temp;

	// Зсув другого рядка на 1 позицію вліво
	temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;

	// Зсув третього рядка на 2 позиції
	temp = state[2]; state[2] = state[10]; state[10] = temp;
	temp = state[6]; state[6] = state[14]; state[14] = temp;

	// Зсув четвертого рядка на 3 позиції
	temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

// InvShiftRows: Зворотний зсув для дешифрування
void aes_invShiftRows(uint8_t* state) {
	uint8_t temp;
	temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
	temp = state[2]; state[2] = state[10]; state[10] = temp;
	temp = state[6]; state[6] = state[14]; state[14] = temp;
	temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
}

// MixColumns: Перемішування колонок матриці стану шляхом множення поліномів
void aes_mixColumns(uint8_t* state) {
	uint8_t Tmp, Tm, t;
	for (int i = 0; i < 16; i += 4) {
		t = state[i] ^ state[i + 1] ^ state[i + 2] ^ state[i + 3];
		Tmp = state[i];
		Tm = state[i] ^ state[i + 1]; Tm = xtime(Tm); state[i] ^= Tm ^ t;
		Tm = state[i + 1] ^ state[i + 2]; Tm = xtime(Tm); state[i + 1] ^= Tm ^ t;
		Tm = state[i + 2] ^ state[i + 3]; Tm = xtime(Tm); state[i + 2] ^= Tm ^ t;
		Tm = state[i + 3] ^ Tmp; Tm = xtime(Tm); state[i + 3] ^= Tm ^ t;
	}
}

// Макрос для загального множення у полі Галуа (для зворотного MixColumns)
#define Multiply(x, y) \
	  (  ((y & 1) * x) ^ \
	  ((y>>1 & 1) * xtime(x)) ^ \
	  ((y>>2 & 1) * xtime(xtime(x))) ^ \
	  ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ \
	  ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

// InvMixColumns: Зворотне перемішування колонок для дешифрування
void aes_invMixColumns(uint8_t* state) {
	uint8_t a, b, c, d;
	for (int i = 0; i < 16; i += 4) {
		a = state[i]; b = state[i + 1]; c = state[i + 2]; d = state[i + 3];
		state[i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[i + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[i + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[i + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// =====================================================================
// ФУНКЦІЇ ОБРОБКИ БЛОКІВ (14 РАУНДІВ AES-256)
// =====================================================================

// Зашифрувати 1 блок даних (рівно 16 байт)
void aes256_encrypt_block(Aes256Ctx* ctx, uint8_t* buf) {

	// Початкове накладання ключа (Initial Round)
	aes_addRoundKey(0, buf, ctx->RoundKey);

	// Основні 13 раундів шифрування
	for (uint8_t round = 1; round < 14; ++round) {
		aes_subBytes(buf);
		aes_shiftRows(buf);
		aes_mixColumns(buf);
		aes_addRoundKey(round, buf, ctx->RoundKey);
	}

	// Фінальний 14-й раунд (Згідно зі стандартом не містить кроку MixColumns)
	aes_subBytes(buf);
	aes_shiftRows(buf);
	aes_addRoundKey(14, buf, ctx->RoundKey);
}

// Розшифрувати 1 блок даних (рівно 16 байт)
void aes256_decrypt_block(Aes256Ctx* ctx, uint8_t* buf) {

	// Дешифрування відбувається у зворотному порядку
	aes_addRoundKey(14, buf, ctx->RoundKey);
	for (uint8_t round = 13; round > 0; --round) {
		aes_invShiftRows(buf);
		aes_invSubBytes(buf);
		aes_addRoundKey(round, buf, ctx->RoundKey);
		aes_invMixColumns(buf);
	}
	aes_invShiftRows(buf);
	aes_invSubBytes(buf);
	aes_addRoundKey(0, buf, ctx->RoundKey);
}

// =====================================================================
// ФАЙЛОВИЙ I/O, РЕЖИМ ЗЧЕПЛЕННЯ БЛОКІВ (CBC) ТА ПАДДІНГ
// =====================================================================

int process_file_aes256_internal(
	const char* in_path,
	const char* out_path,
	const uint8_t* key, // Python через FFI передає масив рівно на 32 байти (256 біт)
	int is_encrypt,
	ProgressCallback callback)
{

	// Відкриття потоків для читання та запису у бінарному режимі
	std::ifstream fin(in_path, std::ios::binary);
	if (!fin.is_open()) return -1;
	std::ofstream fout(out_path, std::ios::binary);
	if (!fout.is_open()) return -1;

	// Ініціалізація контексту AES-256 (генерація раундових ключів)
	Aes256Ctx ctx;
	aes256_init(&ctx, key);

	// Визначення розміру файлу для коректного розрахунку відсотків прогресу
	fin.seekg(0, std::ios::end);
	long long file_size = fin.tellg();
	fin.seekg(0, std::ios::beg);
	long long processed = 0;
	int last_percent = -1;

	uint8_t iv[16] = { 0 }; // Вектор ініціалізації (IV) для режиму CBC. За замовчуванням заповнений нулями

	if (is_encrypt) {

		// Шифрування
		while (fin) {
			uint8_t buffer[16] = { 0 };
			fin.read(reinterpret_cast<char*>(buffer), 16);
			int bytes_read = static_cast<int>(fin.gcount());

			// СТАНДАРТ ДОПОВНЕННЯ (Padding) PKCS#7
			// Якщо блок неповний, заповнюємо його байтами, значення яких дорівнює їхній кількості
			if (bytes_read == 0) {
				// Якщо розмір файлу ідеально кратний 16, стандарт вимагає додати 
				// один повністю новий блок, заповнений числом 16 (0x10)
				for (int j = 0; j < 16; ++j) buffer[j] = 0x10;
				bytes_read = 16;
			}
			else if (bytes_read < 16) {
				// Якщо не вистачає кількох байтів, заповнюємо їх відповідним значенням
				uint8_t pad_val = 16 - bytes_read;
				for (int j = bytes_read; j < 16; ++j) buffer[j] = pad_val;
				bytes_read = 16;
			}

			// РЕЖИМ CBC (Cipher Block Chaining)
			// Накладання (XOR) відкритого тексту на попередній зашифрований блок
			for (int i = 0; i < 16; ++i) buffer[i] ^= iv[i];

			// Безпосередньо шифрування 16-байтного блоку ядром AES-256
			aes256_encrypt_block(&ctx, buffer);

			// Оновлення вектора ініціалізації: поточний шифротекст стає IV для наступного циклу
			for (int i = 0; i < 16; ++i) iv[i] = buffer[i];

			// Запис зашифрованого блоку у вихідний файл
			fout.write(reinterpret_cast<char*>(buffer), 16);

			// Розрахунок прогресу для GUI на Python
			processed += fin.gcount();
			int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
			if (percent != last_percent && callback) { callback(percent); last_percent = percent; }
			if (fin.eof()) break;
		}
	}
	else { // Дешифровка
		uint8_t prev_iv[16];
		for (int i = 0; i < 16; ++i) prev_iv[i] = iv[i];

		while (fin) {
			uint8_t buffer[16] = { 0 };
			fin.read(reinterpret_cast<char*>(buffer), 16);
			if (fin.gcount() == 0) break;

			// Зберігаємо поточний блок шифротексту ДО дешифрування
			// Він стане вектором ініціалізації (IV) для наступного блоку
			uint8_t current_cipher[16];
			for (int i = 0; i < 16; ++i) current_cipher[i] = buffer[i];

			// Дешифрування блоку ядром AES-256
			aes256_decrypt_block(&ctx, buffer);

			// РЕЖИМ CBC (Зворотна операція)
			// Накладання (XOR) результату дешифрування на попередній шифротекст
			for (int i = 0; i < 16; ++i) {
				buffer[i] ^= prev_iv[i];
				prev_iv[i] = current_cipher[i];
			}

			// ЗНЯТТЯ ДОПОВНЕННЯ (Unpadding) PKCS#7
			// Виконується тільки для останнього блоку файлу
			if (fin.peek() == EOF) {
				// В PKCS#7 останній байт завжди містить кількість доданих байтів
				uint8_t pad_val = buffer[15];
				int valid_bytes = 16;

				// Базова перевірка цілісності: значення має бути від 1 до 16
				if (pad_val > 0 && pad_val <= 16) {
					valid_bytes = 16 - pad_val;
				}

				// Записуємо тільки корисні дані (відкидаємо байти доповнення)
				fout.write(reinterpret_cast<char*>(buffer), valid_bytes);
			}
			else {
				// Якщо це не останній блок - записуємо всі 16 байт
				fout.write(reinterpret_cast<char*>(buffer), 16);
			}

			// Розрахунок прогресу для GUI на Python
			processed += 16;
			int percent = (file_size == 0) ? 100 : static_cast<int>((processed * 100) / file_size);
			if (percent != last_percent && callback) { callback(percent); last_percent = percent; }
		}
	}

	secure_memory_scrub(&ctx, sizeof(ctx));
	secure_memory_scrub(iv, sizeof(iv));

	return 0;
}