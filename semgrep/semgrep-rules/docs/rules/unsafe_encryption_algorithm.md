# unsafe_encryption_algorithm.yaml

Правило для детектирования использования слабых алгоритмов шифрования DES, 3DES и RC4 в Go. Эти алгоритмы криптографически сломаны и не должны использоваться для защиты данных.

## Метаданные

- **Rule ID:** `unsafe-encryption-algorithm`
- **Severity:** HIGH
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **OWASP:** A02:2025 - Cryptographic Failures
- **Language:** Go
- **Confidence:** HIGH

## Описание уязвимости

DES, 3DES и RC4 — устаревшие алгоритмы шифрования с критическими уязвимостями. DES имеет слишком короткий ключ (56 бит), 3DES медленный и уязвим к атакам, RC4 имеет предсказуемые паттерны в keystream. Все они считаются небезопасными для современного использования.

**Последствия:**

- Расшифровка зашифрованных данных злоумышленником
- Brute-force атаки за приемлемое время
- Компрометация конфиденциальных данных
- Нарушение compliance требований (PCI DSS запрещает использование DES/3DES)

## Как работает правило

Правило ищет три паттерна использования слабых алгоритмов:

### 1. DES cipher

```yaml
pattern: des.NewCipher($DATA)
```

Детектирует создание DES cipher'а. DES использует 56-битный ключ, который можно взломать brute-force за часы.

## 2. Triple DES (3DES)

```jsx
pattern: des.NewTripleDESCipher($DATA)
```

3DES применяет DES три раза для увеличения длины ключа, но он медленный и уязвим к атакам (Sweet32).

## 3. RC4 stream cipher

```jsx
pattern: rc4.NewCipher($DATA)
```

RC4 имеет bias в keystream, что позволяет атаковать зашифрованные данные (атака на WEP/WPA).

## Метапеременные

- `$DATA` — ключ шифрования (обычно `[]byte`)

## Примеры

## Уязвимо

**Вариант 1: DES для шифрования данных**

```jsx
import "crypto/des"

func encrypt(data, key []byte) ([]byte, error) {
    block, _ := des.NewCipher(key)
    // ... шифрование
}
```

**Вариант 2: 3DES для legacy систем**

```jsx
import "crypto/des"

func encryptLegacy(data, key []byte) ([]byte, error) {
    block, _ := des.NewTripleDESCipher(key)
    // ... шифрование
}
```

**Вариант 3: RC4 stream cipher**

```jsx
import "crypto/rc4"

func encryptStream(data, key []byte) ([]byte, error) {
    cipher, _ := rc4.NewCipher(key)
    // ... шифрование
}
```

**Почему опасно:**

DES можно взломать brute-force за несколько часов, 3DES уязвим к Sweet32 атаке, RC4 имеет предсказуемые паттерны. Все три алгоритма запрещены современными стандартами безопасности.

## Безопасно

**Вариант 1: AES-256**

```jsx
import "crypto/aes"
import "crypto/cipher"

func encrypt(data, key []byte) ([]byte, error) {
    // key должен быть 32 байта для AES-256
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    // ... заполнить nonce случайными данными
    
    return gcm.Seal(nil, nonce, data, nil), nil
}
```

**Вариант 2: ChaCha20-Poly1305 (современная альтернатива)**

```jsx
import "golang.org/x/crypto/chacha20poly1305"

func encrypt(data, key []byte) ([]byte, error) {
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, aead.NonceSize())
    // ... заполнить nonce
    
    return aead.Seal(nil, nonce, data, nil), nil
}
```

## Результаты тестирования

При сканировании **Damn Vulnerable Golang** правило нашло **2 сработки**:

## Находка 1: main.go, строка 88

```jsx
block, _ := des.NewCipher(key)
```

**Статус:** True Positive 

**Критичность:** HIGH — DES используется для шифрования

## Находка 2: main.go, строка 114

```jsx
cipher, _ := rc4.NewCipher([]byte("secret"))
```

**Статус:** True Positive 

**Критичность:** HIGH — RC4 с захардкоженным ключом (двойная проблема!)

## Ограничения правила

Правило **не детектирует:**

1. **Использование через переменные**
    
    ```jsx
    cipherFunc := des.NewCipher  // Присваивание функции
    block, _ := cipherFunc(key)  // Вызов через переменную
    ```
    
2. **Слабые алгоритмы в сторонних библиотеках**
    
    ```jsx
    // Библиотека внутри использует DES
    thirdparty.EncryptData(data)
    ```
    
3. **Legacy протоколы, требующие DES/3DES**
    
    ```jsx
    // Совместимость со старым оборудованием
    legacy.Connect(des.NewCipher(key))
    ```
    

**Примечание:** Использование слабых алгоритмов для обратной совместимости с legacy системами может быть оправдано, но это temporary solution до миграции на современные стандарты.

## False Positives анализ

**Estimated FP Rate:** ~5%

**Возможные причины FP:**

1. **Legacy protocol compatibility**
    
    ```jsx
    // Поддержка старого протокола, требующего 3DES
    block, _ := des.NewTripleDESCipher(key)
    ```
    
2. **Тестовые файлы**
    
    ```jsx
    // crypto_test.go - тестирование совместимости
    func TestDESCompatibility(t *testing.T) {
        block, _ := des.NewCipher(testKey)
    }
    ```
    

## Рекомендации по исправлению

## Главная рекомендация

**Замените DES, 3DES и RC4 на AES-256 с режимом GCM для authenticated encryption.**

**Миграция:**

```jsx
// Уязвимо:
import "crypto/des"
block, _ := des.NewCipher(key)

// Безопасно:
import "crypto/aes"
import "crypto/cipher"

block, err := aes.NewCipher(key) // key = 32 bytes для AES-256
if err != nil {
    return err
}

gcm, err := cipher.NewGCM(block)
if err != nil {
    return err
}
```

## Рекомендации по выбору алгоритма

| **Задача** | **Слабые алгоритмы** | **Надежные алгоритмы** |
| --- | --- | --- |
| Шифрование данных | DES, 3DES, RC4 | AES-256-GCM |
| Шифрование файлов | DES, RC4 | AES-256-GCM, ChaCha20-Poly1305 |
| Stream encryption | RC4 | ChaCha20-Poly1305 |
| Legacy compatibility | DES, 3DES | AES-128 (минимум) |

**AES-256:**

- Стандарт шифрования (NIST, FIPS 140-2)
- 256-битный ключ — защита от brute-force
- Быстрый на современном железе (аппаратная поддержка AES-NI)

**GCM режим:**

- Authenticated encryption (защита от подделки данных)
- Обнаруживает модификацию зашифрованных данных
- Рекомендован NIST

## Для российских стандартов

**ГОСТ Р 34.12-2015 (Кузнечик):**

```jsx
// Использование российского стандарта шифрования
// Требует сторонней библиотеки: github.com/pedroalbanese/gogost
import "github.com/pedroalbanese/gogost/gost3412128"

cipher := gost3412128.NewCipher(key) // 256-bit key
```

**Примечание:** Кузнечик — российский стандарт, рекомендован для госструктур.

## Best Practices

- **AES-256-GCM для большинства задач** — баланс безопасности и производительности
- **ChaCha20-Poly1305 для мобильных устройств** — быстрее без аппаратного AES-NI
- **Случайные nonce/IV** — никогда не переиспользовать для одного ключа
- **Используйте authenticated encryption** — GCM, Poly1305 защищают от подделки