import os
import hashlib
import ctypes
import time

try:
    dll_path = os.path.join(os.path.dirname(__file__), 'CryptoCore.dll')
    crypto_lib = ctypes.CDLL(dll_path)
    
    ProgressCallbackType = ctypes.CFUNCTYPE(None, ctypes.c_int)
    
    process_file_c = crypto_lib.process_file
    process_file_c.argtypes = [
        ctypes.c_char_p,          # in_path
        ctypes.c_char_p,          # out_path
        ctypes.c_char_p,          # algo
        ctypes.POINTER(ctypes.c_uint8), # key
        ctypes.c_int,             # is_encrypt
        ProgressCallbackType      # callback
    ]
    process_file_c.restype = ctypes.c_int
except OSError:
    print("Файл CryptoCore.dll не знайдено!")
    exit()

# Порожній callback для прогрес-бару (нам він у тестах не потрібен)
def dummy_progress(percent):
    pass
c_callback = ProgressCallbackType(dummy_progress)

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()

def get_file_hash(filepath: str) -> str:
    """Обчислює SHA-256 хеш файлу для перевірки цілісності"""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


# ПАРАМЕТРИ ТЕСТУВАННЯ
ALGORITHMS = {
    "SSE XOR": b"SSE_XOR",
    "AES-256": b"aes-256-cbc",
    "3DES": b"des-ede3-cbc",
    "DES": b"des-cbc",
    "Blowfish": b"blowfish-cbc"
}

# Тестові вектори: граничні випадки розмірів файлів
TEST_FILES = {
    "test_0B.bin": 0,           # Пустой файл (проверка паддинга)
    "test_1B.bin": 1,           # 1 байт (неполный блок)
    "test_8B.bin": 8,           # Ровно 8 байт (полный блок DES/Blowfish)
    "test_16B.bin": 16,         # Ровно 16 байт (полный блок AES)
    "test_1MB.bin": 1024 * 1024 # 1 Мегабайт (проверка циклов и буферов)
}

PASSWORD = "123"
KEY_BYTES = derive_key(PASSWORD)
KEY_ARRAY = (ctypes.c_uint8 * 32).from_buffer_copy(KEY_BYTES)


# ЛОГІКА ТЕСТУВАННЯ
def create_test_files():
    print("Створення тестових файлів...")
    for filename, size in TEST_FILES.items():
        with open(filename, 'wb') as f:
            f.write(os.urandom(size)) # Заповнюємо випадковими байтами
        print(f" [+] Створено {filename} ({size} байт)")
    print("-" * 50)

def cleanup_test_files():
    print("\nОчищення тимчасових файлів...")
    for filename in TEST_FILES.keys():
        for ext in ["", ".enc", ".dec"]:
            try:
                os.remove(filename + ext)
            except OSError:
                pass
    print(" [+] Очищення завершено.")

def run_tests():
    create_test_files()
    
    total_tests = len(ALGORITHMS) * len(TEST_FILES)
    passed_tests = 0

    print(f"{'Алгоритм':<15} | {'Файл':<15} | {'Результат':<10} | {'Час (мс)'}")
    print("-" * 60)

    for algo_name, algo_code in ALGORITHMS.items():
        for filename in TEST_FILES.keys():
            enc_file = filename + ".enc"
            dec_file = filename + ".dec"
            
            orig_hash = get_file_hash(filename)

            # ШИФРОВАНИЕ
            start_time = time.perf_counter()
            res_enc = process_file_c(filename.encode(), enc_file.encode(), algo_code, KEY_ARRAY, 1, c_callback)
            
            # РАСШИФРОВКА
            res_dec = process_file_c(enc_file.encode(), dec_file.encode(), algo_code, KEY_ARRAY, 0, c_callback)
            end_time = time.perf_counter()

            elapsed_ms = (end_time - start_time) * 1000

            # ПРОВЕРКА
            if res_enc == 0 and res_dec == 0:
                dec_hash = get_file_hash(dec_file)
                if orig_hash == dec_hash:
                    status = "+ PASS"
                    passed_tests += 1
                else:
                    status = "- FAIL (Hash)"
            else:
                status = f"- FAIL (Code {res_enc}/{res_dec})"

            print(f"{algo_name:<15} | {filename:<15} | {status:<10} | {elapsed_ms:.2f} мс")

    print("-" * 60)
    print(f"РЕЗУЛЬТАТ: Успішно пройдено {passed_tests} з {total_tests} тестів.")
    
    cleanup_test_files()

if __name__ == "__main__":
    run_tests()

	