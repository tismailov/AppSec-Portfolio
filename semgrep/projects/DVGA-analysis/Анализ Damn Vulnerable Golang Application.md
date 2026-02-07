# Анализ Damn Vulnerable Golang Application

Клонируем репозиторий проекта

```jsx
git clone [https://github.com/TheHackerDev/damn-vulnerable-golang.git](https://github.com/TheHackerDev/damn-vulnerable-golang.git)
```

Перейдем в директорию проекта и запустим сканирование при помощи команды

```jsx
semgrep scan --config ~/semgrep-rules/go/ --text
```

где флаг --config ~/semgrep-rules/go/ означает запуск сканирования с правилами для языка Go, а --text — вывод результата сканирования в терминал

После сканирования получаем следующий результат:

```jsx
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
• Findings: 11 (11 blocking)
• Rules run: 82
• Targets scanned: 1
• Parsed lines: ~100.0%
• Scan was limited to files tracked by git
• For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 82 rules on 1 file: 11 findings.
```

Анализатор нашел 11 потенциальных уязвимостей:

1. **Использование слабой библиотеки**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.crypto.math-random-used
Do not use math/rand. Use crypto/rand instead.
    
    ▶▶┆ Autofix ▶ crypto/rand
       13┆ "math/rand"
```

 Функция rand из библиотеки math используется для генерации токена

```jsx
token := rand.Int()
```

Для генерации ключей, токенов и секретов необходимо использовать криптографически надежные библиотеки, например crypto/rand. Уязвимость подтверждена: CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

1. **Выражение, всегда возвращающее True**

```
 ❱ home.taga.semgrep-rules.go.lang.correctness.eqeq-is-bad
          Detected useless comparison operation `password == password` or `password !=  
          password`. This will always return 'True' or 'False' and therefore is not     
          necessary. Instead, remove this comparison operation or use another comparison
          expression that is not deterministic.                                         
                                                                                        
           27┆ if password == "secret123" {

```

В коде константной переменной password присваивается значение secret123, после чего производится проверка переменной password == “secret123”: 

```jsx
const password = "secret123"
if password == "secret123" {
		fmt.Println("Access granted!")
}
```

Semgrep детектировал детерминистичное сравнение. Реальная уязвимость — hardcoded password. Рекомендация: вынести в переменные окружения или secrets manager.

1. **Использование слабой hash функции**

```jsx
❱ home.taga.semgrep-rules.go.lang.security.audit.crypto.use-of-md5
          Detected MD5 hash algorithm which is considered insecure. MD5 is not collision     
          resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or
          SHA3 instead.                                                                      
                                                                                             
           36┆ hash := md5.New()

```

В коде используется слабая криптографическая хэш функция MD5. Данная функция уязвима к атакам коллизий. Несмотря на то, что MD5 можно использовать для подсчета контрольной суммы, как например в GitHub для контроля версий, в большинстве случаев рекомендуется использовать криптографический стойкие хэш функции: SHA256, SHA3. Для хранения хэшей паролей — Argon2. Уязвимость: CWE-327: Use of a Broken or Risky Cryptographic Algorithm

1. **Запись файла без валидации**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.xss.no-direct-write-to-responsewriter
          Detected directly writing or similar in 'http.ResponseWriter.write()'. This        
          bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead,
          use the 'html/template' package and render data using 'template.Execute()'.        
                                                                                             
           52┆ w.Write(data)

```

В коде можно увидеть следующую функцию:

```jsx
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		filePath := r.URL.Query().Get("path")
		data, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})
```

При выполнении функции http.ResponseWriter.write() валидация файла не выполняется, что влечет за собой уязвимость к XSS и XEE инъекциям. Рекомендуется использовать безопасную функцию: html/template.Execute(). Уязвимость CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

1. **Отсутствие валидации параметров при передаче в SQL запрос**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.database.string-formatted-query
          String-formatted SQL query detected. This could lead to SQL injection if the string
          is not sanitized properly. Audit this call to ensure the SQL is not manipulable by 
          external data.                                                                     
                                                                                             
           78┆ query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND
               password='%s'", username, pass) 
```

Переменные username и pass передаются в SQL-запрос напрямую, без валидации, что порождает уязвимость к SQL-инъекции. Рекомендуется использовать библиотеку database/sql, содержащую параметризированные запросы. Уязвимость CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

1. **Уязвимость к SQL-инъекции**

```jsx
❯❯❱ home.taga.semgrep-rules.go.lang.security.audit.sqli.gosql-sqli
          Detected string concatenation with a non-literal variable in a "database/sql" Go  
          SQL statement. This could lead to SQL injection if the variable is user-controlled
          and not properly sanitized. In order to prevent SQL injection, use parameterized  
          queries or prepared statements instead. You can use prepared statements with the  
          'Prepare' and 'PrepareContext' calls.                                             
                                                                                            
           80┆ db.Exec(query)

```

Данная сработка описывает выполнение уязвимого SQL запроса из сработки 5.

1. Использование слабых криптографических алгоритмов

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.crypto.use-of-DES
          Detected DES cipher algorithm which is insecure. The algorithm is considered weak
          and has been deprecated. Use AES instead.                                        
                                                                                           
           88┆ block, _ := des.NewCipher(key)

```

В 88 строчке можно увидеть шифрование при помощи шифра DES. Данный шифр является устаревшим, вместо него лучше использовать AES, Кузнечик. Уязвимость CWE-327: Use of a Broken or Risky Cryptographic Algorithm

1. **Использование устаревшего протокола**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.crypto.ssl-v3-is-insecure
          SSLv3 is insecure because it has known vulnerabilities. Starting with go1.14, SSLv3
          will be removed. Instead, use 'tls.VersionTLS13'.                                  
                                                                                             
           ▶▶┆ Autofix ▶ tls.Config{ MinVersion: tls.VersionTLS13, }
           96┆ config := &tls.Config{
           97┆   MinVersion: tls.VersionSSL30,
           98┆ }

```

В 97 строчке кода можно увидеть использование протокола tls.VersionSSL30

```jsx
MinVersion: tls.VersionSSL30,
```

Данный протокол призван небезопасным, поскольку содержит общеизвестные уязвимости. Вместо него рекомендуется использовать протокол tls.VersionSSL30. Уязвимость: CWE-326: Inadequate Encryption Strength

1. **Использование небезопасного алгоритма**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.crypto.use-of-rc4
          Detected RC4 cipher algorithm which is insecure. The algorithm has many known
          vulnerabilities. Use AES instead.                                            
                                                                                       
          114┆ cipher, _ := rc4.NewCipher([]byte("secret"))
```

Данный алгоритм призван небезопасным, поскольку содержит общеизвестные уязвимости. Вместо него рекомендуется использовать алгоритм AES. Уязвимость: CWE-327: Use of a Broken or Risky Cryptographic Algorithm

1. **Уязвимость к DOS**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.potential-dos-via-decompression-bomb
          Detected a possible denial-of-service via a zip bomb attack. By limiting the max
          bytes read, you can mitigate this attack. `io.CopyN()` can specify a size.      
                                                                                          
           ▶▶┆ Autofix ▶ io.CopyN(os.Stdout,  gzr, 1024*1024*256)
          149┆ _, _ = io.Copy(os.Stdout, gzr)

```

Функция io.Copy копирует все данные без ограничений из gzip-потока. Если злоумышленник передаст zip-бомбу, система начнет декомпрессию огромного количества байт, что приведет к исчерпанию памяти и CPU. Рекомендуется использование io.CopyN для ограничения максимального объема читаемых данных. Уязвимость CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)

1. **Использование небезопасного протокола**

```jsx
❯❱ home.taga.semgrep-rules.go.lang.security.audit.net.use-tls
          Found an HTTP server without TLS. Use 'http.ListenAndServeTLS' instead. See
          https://golang.org/pkg/net/http/#ListenAndServeTLS for more information.   
                                                                                     
           ▶▶┆ Autofix ▶ http.ListenAndServeTLS(":8080", certFile, keyFile, nil)
          152┆ log.Fatal(http.ListenAndServe(":8080", nil))
```

В данной сработке указано использование протокола HTTP, который в свою очередь передает данные в открытом виде. Рекомендуется использовать HTTPS с поддержкой TLS шифрования. Уязвимость:  CWE-1428: Reliance on HTTP instead of HTTPS