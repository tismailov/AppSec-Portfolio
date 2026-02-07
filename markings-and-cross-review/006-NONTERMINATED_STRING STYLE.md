# 006-NONTERMINATED_STRING.STYLE

Тип задачи: Разметка сработки
Оценка: False Positive

Описание: Копирование из строки tok->cur в &tok_mode->last_expr_buffer[tok_mode->last_expr_size] без null-терминации в lexer.c:229. Длина исходной строки вычисляется с помощью функции strlen в lexer.c:212.

```c
strncpy(tok_mode->last_expr_buffer + tok_mode->last_expr_size, tok->cur, size);
```

Анализ сработки:

1. Переменная size содержит длину строки tok->cur, вычисленную через strlen:

```c
Py_ssize_t size = strlen(tok->cur);
```

1. Буфер last_expr_buffer используется для накопления данных порциями в рамках функции _PyLexer_update_fstring_expr. В случае case 0: происходит дописывание данных в конец существующего буфера:

```c
char *new_buffer = PyMem_Realloc(
tok_mode->last_expr_buffer,
tok_mode->last_expr_size + size
);
tok_mode->last_expr_buffer = new_buffer;
strncpy(tok_mode->last_expr_buffer + tok_mode->last_expr_size, tok->cur, size);
tok_mode->last_expr_size += size;
```

1. Буфер last_expr_buffer является промежуточным хранилищем для аккумуляции данных и используется с явным отслеживанием размера через поле last_expr_size. Внутри функции буфер обрабатывается только с указанием размера и не используется как null-terminated C-строка. Отсутствие \0 после вызова strncpy() в данном контексте является корректным паттерном работы с динамическими буферами, где null-терминатор не требуется на промежуточных этапах накопления данных.

Вердикт: False Positive