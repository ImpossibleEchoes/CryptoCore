#pragma once
#include <inttypes.h>

typedef void (*ProgressCallback)(int);

// Функція для гарантованого затирання пам'яті. 
// Ключове слово volatile змушує компілятор виконати кожну операцію запису ігноруючи будь-які спроби оптимізації
__forceinline void secure_memory_scrub(void* v, size_t n) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(v);
    while (n--) {
        *p++ = 0x00; // Перезаписуємо оперативну пам'ять нулями
    }
}