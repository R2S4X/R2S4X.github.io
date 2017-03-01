---
layout: "post"
title: "[Xiomara CTF 2017] Crapsoft Activator writeup"
date: "2017-03-01 13:41"
category: writeup
---

**Задание**: [CrapsoftActivator.zip]({{ site.url }}/download/CrapsoftActivator.zip)

Открыв задание сразу же замечаю это
```
.text:0000000000400F4C     mov     rax, 9F0E4EBA1FDEA48Fh
.text:0000000000400F56     mov     [rbp+N], rax
.text:0000000000400F5A     mov     [rbp+E], 10001h
```
Вообще не думая решаю что это RSA и иду факторизировать `0x9F0E4EBA1FDEA48F`. И да, получаю 2 множителя
```
Sun Feb 26 09:37:11 2017  p10 factor: 3331142873
Sun Feb 26 09:37:11 2017  p10 factor: 3440616359
```
Считаю `D` даже не задумываясь а нужно ли это вообще, т.к. дальше код я в глаза еще не видел, но мало ли, вдруг пригодится :) И да, дальше оно пригодится, это можно будет увидеть чуть ниже

```
.text:0000000000401007     mov     esi, offset aEnterActivatio ; "Enter Activation code: "
.text:000000000040100C     mov     edi, offset unk_7ABC80
.text:0000000000401011     call    sub_41F190
.text:0000000000401016     mov     esi, offset sub_401226
.text:000000000040101B     mov     edi, offset unk_7ABDA0
.text:0000000000401020     call    sub_43B700
.text:0000000000401025     mov     rdx, rax
.text:0000000000401028     lea     rax, [rbp+M]
.text:000000000040102C     mov     rsi, rax
.text:000000000040102F     mov     rdi, rdx
.text:0000000000401032     call    sub_43DE10
.text:0000000000401037     mov     rax, [rbp+M]
.text:000000000040103B     mov     rdx, [rbp+N]
.text:000000000040103F     mov     rcx, [rbp+E]
.text:0000000000401043     mov     rsi, rcx
.text:0000000000401046     mov     rdi, rax
.text:0000000000401049     call    pow
.text:000000000040104E     mov     [rbp+C], rax
.text:0000000000401052     mov     rax, [rbp+C]
.text:0000000000401056     cmp     rax, [rbp+name]
```
С помощью этих ключей шифруется код активации и сравнивает с имени, если они равны, то все хорошо.

Имя берется не все, а только лишь последнии 8 символов от имени, например
```
R2S4X -> R2S4X
1234567890 -> 34567890
```
Для того что бы получить код активации нужно принять, что имя это криптотекст и нужно его расшифровать, для этого как раз и пригодится значение `D`, которое нашли в самом начале
```
code = Name ^ D % N
```
Я написал универсальный генератор, который дает код для любого имени
``` python
N = 11461184663010059407
D = 8982944154482758241

def get_code(name):
    C = int(name[-8:].encode('hex'), 16)
    code = pow(C, D, N)

name = raw_input('Name: ')
print('%x' % get_code(name))
```
Но т.к. код нужен для имени `badr00t`, флаг будет
```
xiomara{8504062a19e2e216}
```
