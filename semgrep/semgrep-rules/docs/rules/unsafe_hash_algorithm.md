# unsafe_hash_algorithm.yaml

Правило для детектирования использования слабых хеш-функций MD5 и SHA-1 в Go. Эти алгоритмы уязвимы к коллизиям и не должны использоваться для криптографических целей.

## Метаданные

- **Rule ID:** `unsafe-hash-algorithm`
- **Severity:** HIGH
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **OWASP:** A02:2025 - Cryptographic Failures
- **Language:** Go
- **Confidence:** HIGH

## Описание уязвимости

MD5 и SHA-1 — устаревшие хеш-функции, криптографически сломанные из-за уязвимости к collision attacks (коллизиям). Злоумышленник может создать два разных файла с одинаковым хешем, что делает эти алгоритмы непригодными для проверки целостности, цифровых подписей или хранения паролей.

**Последствия:**

- Подделка цифровых подписей
- Bypass проверки целостности файлов
- Collision attacks на SSL-сертификатах
- Небезопасное хранение паролей

## Как работает правило

Правило ищет четыре паттерна использования MD5 и SHA-1:

### 1. Создание MD5 hasher

```yaml
pattern: md5.New()
```

Детектирует инициализацию MD5-хешера для последовательного хеширования данных.

## 2. Прямое вычисление MD5

```jsx
pattern: md5.Sum($DATA)
```

Ловит одношаговое вычисление MD5-хеша от массива байт.

## 3. Создание SHA-1 hasher

```jsx
pattern: sha1.New()
```

Аналогично MD5, но для SHA-1.

## 4. Прямое вычисление SHA-1

```jsx
pattern: sha1.Sum($DATA)
```

Одношаговое вычисление SHA-1-хеша.

## Метапеременные

- `$DATA` — данные для хеширования (обычно `[]byte`)

## Примеры

## Уязвимо

**Вариант 1: MD5 для хеширования паролей**

```jsx
import "crypto/md5"

func hashPassword(password string) string {
    hash := md5.New()
    hash.Write([]byte(password))
    return hex.EncodeToString(hash.Sum(nil))
}
```

**Вариант 2: SHA-1 для проверки целостности**

```jsx
import "crypto/sha1"

func checkFileIntegrity(filePath string) (string, error) {
    data, _ := os.ReadFile(filePath)
    hash := sha1.Sum(data)
    return hex.EncodeToString(hash[:]), nil
}
```

**Почему опасно:**

MD5 и SHA-1 можно взломать за секунды на современном оборудовании. Для паролей — существуют rainbow tables. Для файлов — злоумышленник может создать подделку с тем же хешем.

## Безопасно

**Вариант 1: SHA-256 для общих целей**

```jsx
import "crypto/sha256"

func hashPassword(password string) string {
    hash := sha256.New()
    hash.Write([]byte(password))
    return hex.EncodeToString(hash.Sum(nil))
}
```

**Вариант 2: SHA-512 для повышенной безопасности**

```jsx
import "crypto/sha512"

func checkFileIntegrity(filePath string) (string, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return "", err
    }
    hash := sha512.Sum512(data)
    return hex.EncodeToString(hash[:]), nil
}
```

**Вариант 3: bcrypt для паролей**

```jsx
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash), err
}
```

## Результаты тестирования

При сканировании **Damn Vulnerable Golang** правило нашло:

```jsx
// main.go:36
hash := md5.New()
```

**Статус:** True Positive 

**Критичность:** HIGH — MD5 использован для криптографических целей

## Ограничения правила

Правило **не детектирует:**

1. **Использование через переменные**
    
    ```jsx
    hashFunc := md5.New  // Присваивание функции в переменную
    h := hashFunc()      // Вызов через переменную
    ```
    
2. **MD5/SHA-1 в сторонних библиотеках**
    
    ```jsx
    // Библиотека внутри использует MD5, но снаружи не видно
    thirdparty.HashData(data)
    ```
    
3. **Легитимное использование для non-crypto целей**
    
    ```jsx
    // MD5 для ETag в HTTP (не security-критично)
    etag := md5.Sum([]byte(content))
    ```
    

## False Positives анализ

**Estimated FP Rate:** ~5-10%

**Возможные причины FP:**

1. **Non-cryptographic checksums**
    
    ```jsx
    // MD5 для быстрой проверки дубликатов файлов (не security)
    hash := md5.Sum(fileContent)
    dedupMap[hash] = filePath
    ```
    
2. **Legacy protocol compatibility**
    
    ```jsx
    // Поддержка старого API, который требует MD5
    signature := md5.Sum([]byte(legacyData))
    ```
    

## Рекомендации по исправлению

## Главная рекомендация

**Замените MD5 и SHA-1 на SHA-256 или SHA-512 для всех криптографических целей.**

**Миграция:**

```jsx
// Уязвимо:
import "crypto/md5"
hash := md5.New()

// Безопасно:
import "crypto/sha256"
hash := sha256.New()
```

## Рекомендации по использованию

| **Задача** | Слабые алгоритмы | Надежные алгоритмы |
| --- | --- | --- |
| Хеширование паролей | MD5, SHA-1, SHA-256 | bcrypt, argon2, scrypt |
| Проверка целостности | MD5, SHA-1 | SHA-256, SHA-512 |
| Цифровые подписи | MD5, SHA-1 | SHA-256, SHA-512 |
| HMAC | MD5, SHA-1 | SHA-256, SHA-512 |
| Non-crypto checksums | — | MD5 допустим (но лучше SHA-256) |

## Для хеширования паролей

**Не используйте обычные хеш-функции:**

```jsx
// Небезопасно даже с SHA-256:
hash := sha256.Sum256([]byte(password))
```

**Используйте специализированные функции:**

```jsx
// bcrypt:
import "golang.org/x/crypto/bcrypt"
hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)

// argon2:
import "golang.org/x/crypto/argon2"
hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
```

## Best Practices

- **SHA-256 для общих целей** — баланс скорости и безопасности
- **SHA-512 для чувствительных данных** — более стойкий к атакам
- **bcrypt/argon2 для паролей** — защита от rainbow tables и brute-force
- **Избегайте MD5 везде** — даже для non-crypto целей лучше SHA-256