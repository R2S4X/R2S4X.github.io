---
layout: "post"
title: "[Xiomara CTF 2017] EasyPie writeup"
date: "2017-02-28 21:14"
category: writeup
---

**Задание**: [easypie.zip]({{ site.url }}/download/easypie.zip)

Дан дизасм листинг байткода python. Собственно нужно понять, что он делает и получить флаг.

Сначала идет инициализация списка `res`
```
4           0 LOAD_CONST               1 (0)
            3 LOAD_CONST               2 (-15)
            6 LOAD_CONST               3 (6)
            9 LOAD_CONST               4 (-2)
           12 LOAD_CONST               5 (-12)
           15 LOAD_CONST               6 (17)
           18 LOAD_CONST               7 (-17)
           21 LOAD_CONST               8 (26)
           24 LOAD_CONST               9 (-4)
           27 LOAD_CONST              10 (-68)
           30 LOAD_CONST              11 (44)
           33 LOAD_CONST              12 (20)
           36 LOAD_CONST              13 (-6)
           39 LOAD_CONST              14 (-61)
           42 LOAD_CONST              15 (59)
           45 LOAD_CONST              16 (-56)
           48 LOAD_CONST              11 (44)
           51 LOAD_CONST              17 (5)
           54 LOAD_CONST              17 (5)
           57 LOAD_CONST              18 (-69)
           60 LOAD_CONST              19 (61)
           63 LOAD_CONST              14 (-61)
           66 LOAD_CONST               1 (0)
           69 LOAD_CONST              20 (15)
           72 LOAD_CONST              21 (58)
           75 LOAD_CONST              22 (-11)
           78 LOAD_CONST              23 (10)
           81 LOAD_CONST              24 (-57)
           84 LOAD_CONST              25 (49)
           87 LOAD_CONST              26 (-5)
           90 LOAD_CONST              27 (13)
           93 LOAD_CONST              24 (-57)
           96 LOAD_CONST               1 (0)
           99 LOAD_CONST              28 (4)
          102 LOAD_CONST              29 (70)
          105 BUILD_LIST              35
          108 STORE_FAST               0 (res)
```
Что соответствует этому
``` python
res = [
    0, -15, 6, -2, -12, 17, -17, 26, -4, -68, 44, 20, -6,
    -61, 59, -56, 44, 5, 5, -69, 61, -61, 0, 15, 58, -11,
    10, -57, 49, -5, 13, -57, 0, 4, 70,
]
```
Далее инициализируются еще две переменные
```
5         111 LOAD_CONST              30 ('x')
          114 STORE_FAST               1 (start)

6         117 LOAD_CONST              31 ('')
          120 STORE_FAST               2 (flag)
```
``` python
start = 'x'
flag = ''
```
Далее идет обявления цикла
```
8         123 SETUP_LOOP              46 (to 172)
          126 LOAD_FAST                0 (res)
          129 GET_ITER            
      >>  130 FOR_ITER                38 (to 171)
          133 STORE_FAST               3 (i)
```
Что означает
``` python
for i in res:
```
Дальше идут действия внутри цикла с даными, которые инициализировались выше
```
9         136 LOAD_GLOBAL              0 (chr)
          139 LOAD_GLOBAL              1 (ord)
          142 LOAD_FAST                1 (start)
          145 CALL_FUNCTION            1
          148 LOAD_FAST                3 (i)
          151 BINARY_ADD          
          152 CALL_FUNCTION            1
          155 STORE_FAST               1 (start)
```
``` python
start = chr(ord(start) + i)
```
И формирование флага
```
10         158 LOAD_FAST                2 (flag)
           161 LOAD_FAST                1 (start)
           164 INPLACE_ADD         
           165 STORE_FAST               2 (flag)
           168 JUMP_ABSOLUTE          130
       >>  171 POP_BLOCK           
```
``` python
flag += start
```
И в конце идет вывод флага
```
11     >>  172 LOAD_FAST                2 (flag)
           175 PRINT_ITEM          
           176 PRINT_NEWLINE       
           177 LOAD_CONST               0 (None)
           180 RETURN_VALUE        
```
В куче это выглядит так
``` python
res = [
    0, -15, 6, -2, -12, 17, -17, 26, -4, -68, 44, 20, -6,
    -61, 59, -56, 44, 5, 5, -69, 61, -61, 0, 15, 58, -11,
    10, -57, 49, -5, 13, -57, 0, 4, 70,
]
start = 'x'
flag = ''
for i in res:
    start = chr(ord(start) + i)
    flag += start
print (flag)
```
И получаем флаг
```
xiomara{w3_sm0k3_di$a$$3mbl3d_l337}
```
