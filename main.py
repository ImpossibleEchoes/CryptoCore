import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import ctypes
import os
import hashlib
import threading

# Завантажуємо DLL
try:
    dll_path = os.path.join(os.path.dirname(__file__), 'CryptoCore.dll')
    crypto_lib = ctypes.CDLL(dll_path)
    
    # Визначаємо тип функції Callback (приймає int, нічого не повертає)
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
    print("Помилка: не знайдено CryptoCore.dll.")
    exit()

def derive_key(password: str) -> bytes:
    # SHA-256 завжди генерує 32 байти. 
    # Цього вистачить і для AES-256, і для DES, і для нашого XOR.
    return hashlib.sha256(password.encode('utf-8')).digest()

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("duplom")
        self.geometry("450x320")
        self.resizable(False, False)

        self.filepath = None

        # Вибір файлу
        self.btn_select = tk.Button(self, text="Обрати файл", command=self.select_file, width=20)
        self.btn_select.pack(pady=10)

        self.lbl_file = tk.Label(self, text="Файл не обрано", fg="gray")
        self.lbl_file.pack()

        # Вибір алгоритму
        tk.Label(self, text="Алгоритм:").pack(pady=(5, 0))
        self.algo_var = tk.StringVar()
        self.algo_cb = ttk.Combobox(self, textvariable=self.algo_var, state="readonly", width=25)
        # Внутрішні назви OpenSSL для алгоритмів
        self.algo_map = {
            "Швидкий SSE XOR": b"SSE_XOR",
            "AES-256-CBC": b"aes-256-cbc",
            "3DES-CBC": b"des-ede3-cbc",
            "DES-CBC": b"des-cbc",
            "Blowfish-CBC": b"blowfish-cbc"
        }
        self.algo_cb['values'] = list(self.algo_map.keys())
        self.algo_cb.current(0)
        self.algo_cb.pack()

        # Пароль
        tk.Label(self, text="Введіть пароль:").pack(pady=(10, 0))
        self.entry_password = tk.Entry(self, show="*", width=30)
        self.entry_password.pack()

        # Кнопки дії
        frame_btns = tk.Frame(self)
        frame_btns.pack(pady=15)
        self.btn_enc = tk.Button(frame_btns, text="Зашифрувати", command=lambda: self.run_crypto(1), bg="#f44336", fg="white", width=15)
        self.btn_enc.pack(side=tk.LEFT, padx=5)
        self.btn_dec = tk.Button(frame_btns, text="Розшифрувати", command=lambda: self.run_crypto(0), bg="#4CAF50", fg="white", width=15)
        self.btn_dec.pack(side=tk.LEFT, padx=5)

        # Прогрес
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20)
        
        self.lbl_status = tk.Label(self, text="Очікування...")
        self.lbl_status.pack()

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.lbl_file.config(text=os.path.basename(self.filepath), fg="black")

    def update_progress(self, percent):
        # Цю функцію буде викликати C++ код!
        self.progress_var.set(percent)
        self.lbl_status.config(text=f"Обробка: {percent}%")
        self.update_idletasks()

    def worker_thread(self, in_path, out_path, algo_bytes, key_bytes, is_encrypt):
        key_array = (ctypes.c_uint8 * 32).from_buffer_copy(key_bytes)
        
        # Створюємо C-сумісний вказівник на нашу функцію прогресу
        c_callback = ProgressCallbackType(self.update_progress)

        # Викликаємо DLL
        result = process_file_c(
            in_path.encode('utf-8'),
            out_path.encode('utf-8'),
            algo_bytes,
            key_array,
            is_encrypt,
            c_callback
        )

        if result == 0:
            messagebox.showinfo("Успіх", "Операцію успішно завершено!")
        elif result == -1:
            messagebox.showerror("Помилка", "Не вдалося відкрити файли для читання/запису.")
        
        # Скидаємо інтерфейс
        self.progress_var.set(0)
        self.lbl_status.config(text="Очікування...")
        self.btn_enc.config(state=tk.NORMAL)
        self.btn_dec.config(state=tk.NORMAL)

    def run_crypto(self, is_encrypt):
        if not self.filepath:
            messagebox.showwarning("Увага", "Спочатку оберіть файл!")
            return
        
        password = self.entry_password.get()
        if not password:
            messagebox.showwarning("Увага", "Введіть пароль!")
            return

        if is_encrypt:
            out_path = self.filepath + '.enc'
        else:
            out_path = self.filepath[:-4] if self.filepath.endswith('.enc') else self.filepath + '.dec'

        self.btn_enc.config(state=tk.DISABLED)
        self.btn_dec.config(state=tk.DISABLED)
        
        algo_name = self.algo_var.get()
        algo_bytes = self.algo_map[algo_name]
        key_bytes = derive_key(password)

        # Запускаємо в окремому потоці
        threading.Thread(
            target=self.worker_thread,
            args=(self.filepath, out_path, algo_bytes, key_bytes, is_encrypt),
            daemon=True
        ).start()

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()