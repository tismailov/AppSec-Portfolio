# executing_user_input_on_the_server.yaml

Правило для детектирования OS Command Injection — когда пользовательский ввод передается в exec.Command() и может привести к выполнению произвольных команд на сервере.

## Метаданные

- **Rule ID:** `executing-user-input-on-the-server`
- **Severity:** HIGH
- **CWE:** CWE-78 (OS Command Injection)
- **OWASP:** A03:2025 - Injection
- **Language:** Go
- **Confidence:** HIGH

## Описание уязвимости

Command Injection возникает, когда пользовательский ввод передается в функции выполнения системных команд (например, `exec.Command()`) без должной валидации. Злоумышленник может внедрить собственные команды через специальные символы (`|`, `;`, `&`, `$()` и т.д.).

**Последствия:**

- Выполнение произвольных команд на сервере (Remote Code Execution)
- Чтение/изменение файлов системы
- Установка backdoor'ов
- Lateral movement по инфраструктуре

## Как работает правило

Правило ищет три опасных паттерна использования `exec.Command()`:

### 1. Shell с пользовательским вводом (sh -c)

```yaml
pattern: exec.Command("sh", "-c", $INPUT)
```

Самый опасный вариант — запуск shell с параметром `-c` позволяет выполнять сложные команды с pipe, redirect и т.д.

## 2. Bash с пользовательским вводом

```jsx
pattern: exec.Command("bash", "-c", $INPUT)
```

Аналогично `sh`, но с дополнительными возможностями bash.

## 3. Любая команда с аргументами

```jsx
pattern: exec.Command($CMD, $...ARGS)
```

Более широкий паттерн — ловит вызовы любых команд. Требует manual review, так как может давать False Positives.

## Метапеременные

- `$INPUT` — пользовательский ввод (строка для выполнения)
- `$CMD` — имя команды
- `$...ARGS` — аргументы команды (может быть несколько)

## Примеры

## Уязвимо

**Вариант 1: sh -c с пользовательским вводом**

```jsx
func pingHost(host string) error {
    cmd := exec.Command("sh", "-c", "ping -c 1 " + host)
    return cmd.Run()
}
```

**Вариант 2: Форматирование команды**

```jsx
userInput := r.URL.Query().Get("cmd")
cmd := exec.Command("sh", "-c", userInput)
output, _ := cmd.Output()
```

**Почему опасно:**

Злоумышленник может подставить `host = "8.8.8.8; cat /etc/passwd"` или `userInput = "ls; rm -rf /"` и выполнить произвольные команды.

## Безопасно

**Вариант 1: Прямой вызов команды без shell**

```jsx
// Вместо:
cmd := exec.Command("sh", "-c", "ping -c 1 " + host)

// Используйте:
cmd := exec.Command("ping", "-c", "1", host)
```

При прямом вызове без `sh -c` аргументы передаются напрямую в команду, и shell не интерпретирует специальные символы.

**Вариант 2: Whitelist валидация**

```jsx
func pingHost(host string) error {
    // Проверяем, что host содержит только безопасные символы
    if !regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(host) {
        return errors.New("invalid host format")
    }
    
    cmd := exec.Command("ping", "-c", "1", host)
    return cmd.Run()
}
```

## Результаты тестирования

При сканировании **Damn Vulnerable Golang** правило нашло:

```jsx
// main.go:61
cmd := exec.Command("sh", "-c", userInput)
```

**Статус:** True Positive ✅

**Критичность:** HIGH — позволяет выполнить любую команду на сервере

## Ограничения правила

Правило **не детектирует:**

1. **Command Injection через другие функции**
    
    ```jsx
    // syscall.Exec, os.StartProcess — не покрыты
    syscall.Exec("/bin/sh", []string{"sh", "-c", userInput}, env)
    ```
    
2. **Обфусцированные вызовы**
    
    ```jsx
    // Динамическое построение команды
    shellCmd := "sh"
    cmd := exec.Command(shellCmd, "-c", userInput) // Может не сработать
    ```
    
3. **Command Injection через environment variables**
    
    ```jsx
    cmd := exec.Command("bash")
    cmd.Env = append(os.Environ(), "EVIL="+userInput)
    ```
    

**Примечание:** Третий паттерн (`exec.Command($CMD, $...ARGS)`) очень широкий и может давать False Positives на легитимных вызовах.

## False Positives анализ

**Estimated FP Rate:** ~20-30% (из-за третьего паттерна)

**Возможные причины FP:**

1. **Статические команды без пользовательского ввода**
    
    ```jsx
    // FP — команда статическая, аргументы безопасны
    cmd := exec.Command("git", "status")
    cmd.Run()
    ```
    
2. **Команды с константами**
    
    ```jsx
    const logFile = "/var/log/app.log"
    cmd := exec.Command("tail", "-f", logFile) // FP
    ```
    

**Рекомендация:**

При review проверяйте источник переменных `$CMD` и `$...ARGS`:

- Если из HTTP request, stdin, файла — **True Positive**
- Если константы или внутренняя логика — **False Positive**, можно игнорировать

## Рекомендации по исправлению

### Главная рекомендация

**По возможности вообще не выполнять пользовательский ввод в терминале сервера.**

Большинство задач можно решить безопасными альтернативами:

```go
// Небезопасно:
// Пользователь хочет проверить доступность хоста
cmd := exec.Command("sh", "-c", "ping -c 1 " + host)

// Использование готовых библиотек:
import "github.com/sparrc/go-ping"

pinger, _ := ping.NewPinger(host)
pinger.Count = 1
pinger.Run()

```