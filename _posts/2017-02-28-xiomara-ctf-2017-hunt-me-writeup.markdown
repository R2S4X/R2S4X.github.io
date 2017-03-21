---
layout: "post"
title: "[Xiomara CTF 2017] Hunt Me writeup"
date: "2017-02-28 19:39"
categories: writeup
---

**Задание**: [huntme.zip]({{ site.url }}/download/huntme.zip)

Задание выводит `your flag is :` и какуе-то непонятную строку. Функция `main` как раз и выводит `your flag is :` и больше ничего. В ней еще есть немного антиотладки, но то такое. Раз та строка формируется не в `main` тогда следует проверить нет ли пользовательской функции инициализвции. И она есть!

![]({{ site.url }}/image/huntme_init.png)

В которой происходит ксор фейкового флага с вшитым ключем

![]({{ site.url }}/image/huntme_xor.png)

После этого идет еще одна функция, которая портит его и выводит. Собственно нам нужно только проксорить

![]({{ site.url }}/image/huntme_algo.png)

`xiomara{y0Y_4rE_4_9re47_b0uN7y_hUn7ER!}`
