# 001-DEREF_AFTER_NULL.EX

Тип задачи: Кросс-ревью разметки
Первичная оценка: False Positive
Моя верификация: Согласен — False Positive

**Описание:**
Отсутствие проверки переменной colordb на None перед использованием.

Переменная colordb предается как аргумент в функцию initial_color, однако отсутствует явная проверка на None 

```jsx
red, green, blue = initial_color(initialcolor, colordb)
```

Анализ сработки:

1. Инициализация переменной colordb в строке 132

```jsx
colordb = None
```

1. Цикл проверки colordb на None в строке 136

```python
while colordb is None:
        try:
            colordb = ColorDB.get_colordb(dbfile)
        except (KeyError, IOError):
            pass
        if colordb is None:
            if not files:
                break
            dbfile = files.pop(0)
    if not colordb:
        usage(1, 'No color database file found, see the -d option.')
    s.set_colordb(colordb)

```

1. Если после цикла переменная colordb остается None (проверка `if not colordb:` в строке 145), вызывается функция usage в строке 146

2. В самой же функции usage происходит завершение программы 

```python
def usage(code, msg=''):
    print(docstring())
    if msg:
        print(msg)
    sys.exit(code)
```

1. Можно сделать вывод, что в случае если переменная colordb так и останется None, то произойдет завершение программы
2. Следовательно к моменту вызова функции initial_color в 170 строчке, переменная colordb гарантировано не будет равна None

Вердикт: False Positive