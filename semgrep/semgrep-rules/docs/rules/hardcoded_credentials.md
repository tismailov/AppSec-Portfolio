# hardcoded_credentials.yaml

Правило для детектирования захардкоженных паролей, токенов и API-ключей в исходном коде. Хранение секретов в коде — критическая уязвимость, особенно при использовании Git.

## Метаданные

- **Rule ID:** `hardcoded-credentials`
- **Severity:** HIGH
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **OWASP:** A07:2025 - Identification and Authentication Failures
- **Language:** Go
- **Confidence:** HIGH

## Описание уязвимости

Hardcoded credentials — это хранение паролей, API-ключей, токенов или других секретов непосредственно в исходном коде. Код часто попадает в системы контроля версий (Git), откуда секреты могут утечь через публичные репозитории, логи, или доступ бывших сотрудников.

**Последствия:**

- Утечка учетных данных через публичные репозитории (GitHub, GitLab)
- Компрометация production систем и баз данных
- Невозможность ротации секретов без изменения кода и редеплоя
- Нарушение compliance требований (PCI DSS, SOC 2, GDPR)

## Как работает правило

Правило ищет три паттерна хранения секретов:

### 1. SQL connection string с паролем

```yaml
patterns:
  - pattern-either:
      - pattern: $VAR, $VAR1 := sql.Open($DRIVER, $CREDS)
      - pattern: $VAR, $VAR1 = sql.Open($DRIVER, $CREDS)
  - metavariable-regex:
      metavariable: $CREDS
      regex: '".*(password|passwd|pwd|secret).*"'
```

Ловит строки подключения к БД с явными паролями типа `"user:password@/dbname"`.

## 2. Переменные с секретными именами

```jsx
patterns:
  - pattern: $SECRET := "..."
  - metavariable-regex:
      metavariable: $SECRET
      regex: '(?i)(password|secret|token|api.*key|private.*key)'
```

Детектирует переменные с типичными названиями секретов: `apiKey`, `dbPassword`, `authToken`.

## 3. Константы с секретными именами

```jsx
patterns:
  - pattern: const $SECRET = "..."
  - metavariable-regex:
      metavariable: $SECRET
      regex: '(?i)(password|secret|token|api.*key|private.*key)'
```

Аналогично второму паттерну, но для констант.

## Метапеременные

- `$CREDS` — строка подключения к БД
- `$SECRET` — имя переменной/константы (проверяется regex)
- `$VAR`, `$VAR1` — переменные для результата sql.Open() (например, `db, err`)
- `"..."` — любое строковое значение

## Regex детали

**Для connection strings:**

`text".*(password|passwd|pwd|secret).*"`

- Ищет слова `password`, `passwd`, `pwd`, `secret` внутри строки
- Ловит `"user:password@host"`, `"postgres://user:pwd@localhost"`

**Для имен переменных:**

`text(?i)(password|secret|token|api.*key|private.*key)`

- `(?i)` — регистронезависимый поиск
- `api.*key` — ловит `apiKey`, `api_key`, `API_SECRET_KEY`
- `private.*key` — ловит `privateKey`, `private_rsa_key`

## Примеры

## Уязвимо

**Вариант 1: Константа с паролем**

```jsx
const password = "secret123"
const apiKey = "sk-1234567890abcdef"
```

**Вариант 2: Переменная с токеном**

```jsx
func connectAPI() {
    apiToken := "ghp_xxxxxxxxxxxxxxxxxxxx"
    client := api.NewClient(apiToken)
}
```

**Вариант 3: Connection string с паролем**

```jsx
db, _ := sql.Open("mysql", "user:password@tcp(localhost:3306)/dbname")
db, err := sql.Open("postgres", "postgres://admin:secret123@localhost/mydb")
```

**Почему опасно:**

Если код попадет в публичный репозиторий или будет скомпрометирован, злоумышленник получит доступ к БД, API или другим системам. Смена секрета требует изменения кода, что замедляет реакцию на инцидент.

## Безопасно

**Вариант 1: Переменные окружения**

```jsx
import "os"

func getDBPassword() string {
    password := os.Getenv("DB_PASSWORD")
    if password == "" {
        log.Fatal("DB_PASSWORD environment variable not set")
    }
    return password
}
```

**Вариант 2: Конфигурационные файлы (вне репозитория)**

```jsx
import "github.com/spf13/viper"

viper.SetConfigFile(".env") // Добавить .env в .gitignore!
viper.ReadInConfig()

dbPassword := viper.GetString("DB_PASSWORD")
```

**Вариант 3: Secret Management системы**

```jsx
import "github.com/hashicorp/vault/api"

client, _ := api.NewClient(api.DefaultConfig())
secret, _ := client.Logical().Read("secret/data/myapp/db")
password := secret.Data["password"].(string)
```

## Результаты тестирования

При сканировании **Damn Vulnerable Golang** правило нашло **2 находки**:

## Находка 1: main.go, строка 26

```jsx
const password = "secret123"
```

**Статус:** True Positive ✅

**Риск:** HIGH — пароль в открытом виде

## Находка 2: main.go, строка 79

```jsx
db, _ := sql.Open("mysql", "user:password@/dbname")
```

**Статус:** True Positive ✅

**Риск:** HIGH — учетные данные БД в connection string, более критично чем первая находка

## Ограничения правила

Правило **не детектирует:**

1. **Секреты в байтовых слайсах**
    
    ```jsx
    const jwtSecret = []byte{0x73, 0x65, 0x63, 0x72, 0x65, 0x74} // "secret"
    ```
    
2. **Динамически построенные строки**
    
    ```jsx
    pass := "sec" + "ret" + "123" // Обходит статический анализ
    ```
    
3. **Секреты без ключевых слов в названии**
    
    ```jsx
    const dbConn = "user:a8f7d9c2@localhost" // Пароль есть, но имя переменной не содержит "password"
    ```
    
4. **Секреты в комментариях**
    
    ```jsx
    // TODO: password = admin123
    ```
    

## False Positives анализ

**Estimated FP Rate:** ~10-15%

**Возможные причины FP:**

1. **Тестовые файлы**
    
    ```jsx
    // auth_test.go
    const testPassword = "test123" // FP — тестовые данные, не production
    ```
    
2. **Примеры в документации**
    
    ```jsx
    // Example:
    // apiKey := "your-api-key-here"
    const exampleKey = "example-key-123"
    ```
    
3. **Публичные demo ключи**
    
    ```jsx
    const stripeTestKey = "pk_test_xxxxx" // Stripe test key — безопасно использовать
    ```
    

## Рекомендации по исправлению

## Главная рекомендация

**Никогда не храните секреты в коде. Используйте переменные окружения или secret management системы.**

```jsx
// Уязвимо:
const password = "secret123"

// Безопасно:
password := os.Getenv("APP_PASSWORD")
if password == "" {
    log.Fatal("APP_PASSWORD not set")
}
```

## Best Practices

- **Ротация секретов:** минимум раз в 90 дней
- **Разные секреты для окружений:** dev/staging/prod должны иметь разные пароли
- **Принцип наименьших привилегий:** каждый сервис — свой набор секретов
- **Мониторинг доступа:** логировать использование секретов для аудита