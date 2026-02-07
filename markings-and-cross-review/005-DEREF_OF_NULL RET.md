# 005-DEREF_OF_NULL.RET

Тип задачи: Разметка сработки
Оценка: False Positive

Описание: 
Указатель, возвращенный функцией UVector::elementAt в rbbitblb.cpp

```jsx
 i = static_cast<RBBINode*>(LastPosOfLeftChild->elementAt(ix));
```

может быть NULL и разыменовывается в строке  

```jsx
setAdd(i->fFollowPos, n->fRightChild->fFirstPosSet);
```

без проверки.

Анализ сработки:

1. Переменная ix итерируется строго в границах размера вектора:

```cpp
 for (ix = 0; ix < static_cast<uint32_t>(LastPosOfLeftChild->size()); ix++) {
            i = static_cast<RBBINode*>(LastPosOfLeftChild->elementAt(ix));
            setAdd(i->fFollowPos, n->fRightChild->fFirstPosSet);
```

1. Цикл гарантирует, что индекс ix находится в диапазоне от 0 до (size()-1),
что является валидным диапазоном для вектора. Функция elementAt возвращает
nullptr только при невалидном индексе:

```cpp
void* UVector::elementAt(int32_t index) const {
    return (0 <= index && index < count) ? elements[index].pointer : nullptr;
}
```

1. Поскольку условие (0 <= ix && ix < count) всегда выполняется в рамках
цикла, функция elementAt гарантированно возвращает elements[ix].pointer,
минуя ветку возврата nullptr

Вердикт: False Positive