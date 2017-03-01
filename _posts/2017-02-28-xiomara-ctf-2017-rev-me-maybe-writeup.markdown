---
layout: "post"
title: "[Xiomara CTF 2017] Rev Me Maybe writeup"
date: "2017-02-28 21:37"
category: writeup
---

**Задание**: [RevMeMaybe.zip]({{ site.url }}/download/RevMeMaybe.zip)

Задание получает на вход пароль, проверяет что бы его символы были в диапозоне 0x20-0x7e. Далее проводит небольшие математические действия над ним и сравнивает полученный результат с `0xCEFF5331D4AA`

![]({{ site.url }}/image/revmemaybe_check.png)

Сам алгоритм создания этого значения очень прост. Для этого счетчик умножается на `0x128` и прибавляется символ пароля и так пока не обработаются все символы пароля.

![]({{ site.url }}/image/revmemaybe_calc.png)

Т.к. множитель больше `0x100` следовательно символы пароля никак не накладываются друг на друга. И для того что бы их получить достаточно выполнить обратное действие

``` python
from hashlib import md5

n = 0xCEFF5331D4AA
s = ''
while n > 0:
    s += chr(n % 0x128)
    n //= 0x128

print('xiomara{' + md5(s[::-1]).hexdigest() + '}')
```

```
xiomara{48c92083dc430eb4e8af78a38f9cc877}
```
