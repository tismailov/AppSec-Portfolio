Правило для детектирования SQL-инъекций в Go через fmt.Sprintf() и конкатенацию строк.

Метаданные
Параметр	Значение
Rule ID	unsafe-sql-query
Severity	HIGH
CWE	CWE-89 (SQL Injection)
OWASP	A03:2025 - Injection
Language	Go
Confidence	HIGH
Описание уязвимости
SQL-инъекция возникает, когда пользовательский ввод напрямую встраивается в SQL-запрос через конкатенацию строк или форматирование (fmt.Sprintf).

Последствия
Несанкционированный доступ к данным

Bypass аутентификации

Выполнение произвольных SQL-команд (SELECT, DELETE, DROP TABLE)

Как работает правило
Правило детектирует два опасных паттерна в Go-коде.

Паттерн 1: fmt.Sprintf с SQL-ключевыми словами
Правило ищет использование fmt.Sprintf для формирования SQL-запросов:

text
patterns:
  - pattern-either:
      - pattern: $QUERY = fmt.Sprintf($SQL, $...ARGS)
      - pattern: $QUERY := fmt.Sprintf($SQL, $...ARGS)
  - metavariable-regex:
      metavariable: $SQL
      regex: (?i)".*\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b.*"
Что ловит:

go
// Детектируется
query := fmt.Sprintf("SELECT * FROM users WHERE id=%d", userId)

// Детектируется
query = fmt.Sprintf("DELETE FROM logs WHERE user='%s'", username)
Паттерн 2: Конкатенация строк с SQL
Правило также ловит прямую конкатенацию через оператор +:

text
patterns:
  - pattern-either:
      - pattern: $QUERY = $SQL + $VAR
      - pattern: $QUERY := $SQL + $VAR
  - metavariable-regex:
      metavariable: $SQL
      regex: (?i)".*\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b.*"
Что ловит:

go
// Детектируется
query := "SELECT * FROM users WHERE id=" + userId

// Детектируется  
query = "UPDATE users SET role=" + role + " WHERE id=" + id
Метапеременные
Переменная	Описание
$SQL	Строка с SQL-запросом
$...ARGS	Аргументы форматирования (может быть несколько)
$VAR	Конкатенируемая переменная
$QUERY	Результирующая переменная с запросом
Детали Regex
text
(?i)".*\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b.*"
(?i) — регистронезависимый поиск (ловит SELECT, select, SeLeCt)

\b — граница слова (не ловит SELECTED, INSERTED)

.* — любые символы до/после SQL-команды

SELECT|INSERT|... — список SQL-ключевых слов

Примеры уязвимого кода
Пример 1: fmt.Sprintf с пользовательским вводом
go
func getUserByName(username string) (*User, error) {
    // УЯЗВИМО: прямая подстановка в SQL
    query := fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)
    row := db.QueryRow(query)

    var user User
    err := row.Scan(&user.ID, &user.Name)
    return &user, err
}
Атака:

go
username = "admin' OR '1'='1"

// Результат:
// SELECT * FROM users WHERE username='admin' OR '1'='1'
// → возвращает всех пользователей
Пример 2: Конкатенация строк
go
func deleteUser(userID string) error {
    // УЯЗВИМО: конкатенация
    sql := "DELETE FROM users WHERE id=" + userID
    _, err := db.Exec(sql)
    return err
}
Атака:

go
userID = "1 OR 1=1"

// Результат:
// DELETE FROM users WHERE id=1 OR 1=1
// → удаляет всех пользователей
Пример 3: UNION-based SQL injection
go
func login(username, password string) bool {
    // УЯЗВИМО: обе переменные из пользовательского ввода
    query := fmt.Sprintf(
        "SELECT id FROM users WHERE username='%s' AND password='%s'",
        username, password,
    )

    var id int
    err := db.QueryRow(query).Scan(&id)
    return err == nil
}
Атака:

go
username = "admin' UNION SELECT 1 --"
password = "anything"

// Результат:
// SELECT id FROM users WHERE username='admin' UNION SELECT 1 --' AND password='anything'
// → bypass авторизации
Безопасные альтернативы
Решение 1: Параметризованные запросы (рекомендуется)
go
func getUserByName(username string) (*User, error) {
    // БЕЗОПАСНО: плейсхолдер ?
    query := "SELECT * FROM users WHERE username=?"
    row := db.QueryRow(query, username)

    var user User
    err := row.Scan(&user.ID, &user.Name)
    return &user, err
}
Решение 2: Prepared Statements
go
func login(username, password string) (bool, error) {
    // БЕЗОПАСНО: prepared statement
    stmt, err := db.Prepare("SELECT id FROM users WHERE username=? AND password=?")
    if err != nil {
        return false, err
    }
    defer stmt.Close()

    var id int
    err = stmt.QueryRow(username, password).Scan(&id)
    return err == nil, err
}
Решение 3: ORM с безопасными методами
go
import "gorm.io/gorm"

func getUserByName(db *gorm.DB, username string) (*User, error) {
    // БЕЗОПАСНО: GORM экранирует параметры
    var user User
    result := db.Where("username = ?", username).First(&user)
    return &user, result.Error
}
Результаты тестирования
Damn Vulnerable Golang Application
При сканировании DVGA правило нашло:

Файл: main.go:78

Код:

go
func authenticate(username, password string) bool {
    query := fmt.Sprintf(
        "SELECT * FROM users WHERE username='%s' AND password='%s'",
        username, pass,
    )
    rows, _ := db.Query(query)
    return rows.Next()
}
Вердикт:

Статус: True Positive

Критичность: HIGH

Эксплуатация: Authentication bypass через username = "admin' OR '1'='1"

Ограничения правила
Что НЕ детектируется
ORM с небезопасным использованием

go
// Semgrep не видит
db.Raw("SELECT * FROM users WHERE id=" + userID).Scan(&user)
NoSQL инъекции

go
// MongoDB - вне покрытия правила
filter := bson.M{"username": username}
SQL-инъекции второго порядка

go
// Данные уже в БД, вставлены ранее
db.Query("SELECT * FROM logs WHERE message LIKE '%" + storedValue + "%'")
Рекомендации для расширения
Для GORM/XORM: создать отдельные правила под .Raw(), .Exec()

Для NoSQL: отдельный ruleset под MongoDB/Redis

Статистика
Метрика	Значение
True Positives	1/1 (100%)
False Positives	0
Coverage	SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER
Tested on	Damn Vulnerable Golang Application
Languages	Go 1.16+
Best Practices
Чек-лист безопасного SQL в Go
 Всегда используй плейсхолдеры (?) для пользовательского ввода

 Никогда не конкатенируй строки для SQL

 Используй prepared statements для повторяющихся запросов

 В ORM используй методы с параметрами (Where("id = ?", id))

 Валидируй типы данных (например, strconv.Atoi для ID)

 Логируй SQL-запросы в dev-окружении для аудита

Дополнительная защита
go
// Валидация перед запросом
func validateUsername(username string) error {
    if len(username) > 50 {
        return errors.New("username too long")
    }

    // Только буквы и цифры
    matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", username)
    if !matched {
        return errors.New("invalid username format")
    }

    return nil
}

func getUserByName(username string) (*User, error) {
    // Валидация + параметризованный запрос
    if err := validateUsername(username); err != nil {
        return nil, err
    }

    query := "SELECT * FROM users WHERE username=?"
    row := db.QueryRow(query, username)
    // ...
}
Ссылки
OWASP SQL Injection

CWE-89: SQL Injection

Go database/sql Documentation

Semgrep Rule Syntax
