---
layout: "post"
title: "[ASIS CTF Quals 2017] Unbreakable (rev 193)"
date: "2017-04-10 09:35"
categories: writeup
---

**Задание**: [Unbreakable.zip]({{ site.url }}/download/Unbreakable.zip)

Дан исполняемый файл и зашифрованный файл с флагом. Исполняемый файл читает файл `key`, шифрует его содержимое и записывает в файл `flag.enc`. Вся боль заключается в том, что всё шифрование построено на работе со строками `std::string`. Они отлично экономят время и количество кода при написании программ, но вот при исследовании скомпилированного кода с их использованием да и вообще с использованием `STL`/`Boost`/`Whichever_Templates_Library` это боль и страдание особенно когда скомпилировано с оптимизацией по времени исполнения. И это практически во всех заданиях этого CTF где есть исполняемые файлы. Ну что ж, поплакали и приступим.

Шифрование происходит по-байтово, один байт шифруется в 2 байта. Это происходит посредством преобразование входного байта в двоичное представление и разделения его на 2 части по 4 бита. Далее идет ряд простых арифметических операций, в которых также участвует таблица с константными битами, данные операции проходят отдельно над каждой из частей по 4 бита. На основе этих операций и формируется 2 байта, которые в последствии и записываются в выходной файл.

Для расшифровки достаточно создать таблицу соотношения зашифрованного значения его исходному значению. Но на моем тестовом примере показало, что для значений по четному индексу в файле, нет соответствующего значения в таблице. Как оказалось каждый второй байт сохранялся со свапнутым порядком.

``` python
bits = [
    1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1
]

def encrypt(c):
    n = '{:08b}'.format(c)
    hn = map(int, n[:4])
    ln = map(int, n[4:])
    shn = []
    sln = []
    for i in xrange(7):
        shn.append((hn[0] * bits[i * 4 + 0] + hn[1] * bits[i * 4 + 1] + hn[2] * bits[i * 4 + 2] + hn[3] * bits[i * 4 + 3]) % 2)
        sln.append((ln[0] * bits[i * 4 + 0] + ln[1] * bits[i * 4 + 1] + ln[2] * bits[i * 4 + 2] + ln[3] * bits[i * 4 + 3]) % 2)

    shn.append(1 if sum(shn) else 0)
    sln.append(0 if sum(sln) else 1)

    chn = chr(int(''.join(map(str, shn)), 2))
    cln = chr(int(''.join(map(str, sln)), 2))

    return chn + cln


def decrypt(fname):
    with open(fname, 'rb') as f:
        data = f.read()

    alphabet = {}
    for i in xrange(256):
        alphabet[encrypt(i)] = chr(i)

    s = ''
    for i in xrange(0, len(data), 2):
        key = data[i:i+2]
        if i & 2:
            key = key[::-1]
        s += alphabet[key]
    return s


fname = 'flag.enc_e14e56e1dce4914961d544bd46fc5c7ae21237d7'

data = decrypt(fname)
with open('flag.png', 'wb') as f:
    f.write(data)
```

![]({{ site.url }}/image/unbreakable_flag.png)
