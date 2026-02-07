# 003-BUFFER_OVERFLOW.EX

Тип задачи: Разметка сработки
Оценка: False Positive

Описание: возможность переполнения буфера

Анализатор определил потенциальную проблему при копировании 16 байт из actx->tls_aad в массив storage, начиная с позиции tohash

```jsx
memcpy(tohash, actx->tls_aad, POLY1305_BLOCK_SIZE);
```

Анализ сработки

1. Минимальный размер массива zero — 128, так как 

```jsx
#define CHACHA_BLK_SIZE         64

static const unsigned char zero[4 * CHACHA_BLK_SIZE] = { 0 };
#   else
static const unsigned char zero[2 * CHACHA_BLK_SIZE] = { 0 };
#   endif

// Расчет: zero[2 * CHACHA_BLK_SIZE] = zero[2 * 64] = zero[128]
```

1. Минимальный размер storage — 160, так как количество элементов в массиве рассчитывается следующим образом

```jsx
storage[sizeof(zero) + 32];

// Расчет: storage[sizeof(zero) + 32] = storage[128 + 32] = storage[160];
```

1. Максимальный номер элемента массива storage, на который может указывать buf — 15

```jsx
buf = storage + ((0 - (size_t)storage) & 15);   /* align */
```

1. Указатель tohash определяется как

```jsx
 #define POLY1305_BLOCK_SIZE  16
 #define CHACHA_BLK_SIZE         64
 
 tohash = buf + CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE;
 
 // Расчет: tohash = 15 + 64 - 16 = 63
```

1. Следовательно максимальный номер ячейки массива storage, на который указывает tohash — 63
2. Можно сделать вывод, что при выполнении команды 

```jsx
memcpy(tohash, actx->tls_aad, POLY1305_BLOCK_SIZE),
```

данные будут записаны в элементы с 63 по 78 массива storage.

 78 < 159 (последний допустимый индекс storage), следовательно переполнения не происходит.

Вердикт: False Positive