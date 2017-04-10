---
layout: "post"
title: "[ASIS CTF Quals 2017] Tatter (forensic 281)"
date: "2017-04-10 09:38"
categories: writeup
---

**Задание**: [Tatter_fffdee1378c2c666aa468a59fd22942e71dfbc75]({{ site.url }}/download/Tatter_fffdee1378c2c666aa468a59fd22942e71dfbc75)

Дан архив с 159 файлами по 63 байта каждый. Просмотрев к примеру 5 случайных файлов можно заметить, что в них хотя бы раз, но встретится `IDAT` (но если вы победитель по жизни, то может и не встретите ;) ). Можно предположить, что это разбитая на кусочки PNG картинка, т.к. я до этого уже решил ни одно задание и заметил у них любовь к шифрованию именно этого типа файла, то сомнений не было. Найти начальный кусочек по сигнатуре `\x89PNG` не удалось, но удалось по сигнатуре чанка `IHDR`. Как выяснилось они скипнули первый 7 байт файла, но это не проблема, они постоянные для этого формата. Также они скипнули и последний чанк `IEND`, но как и в предидущем случае это не проблема, т.к. он тоже постоянен.

Задача состоит в том, что бы эти кусочки собрать воедино. На первый взгляд задача не такая и сложная, первый кусочек мы знаем. В нем ищем начало последнего чанка, что бы получить его размер и по нему вычислить сколько нужно кусочков присоединить, что бы чанк был полный. Это все делалось перебором по всем кусочкам, т.к. чанки небольшого размера, то и количество возможных комбинаций было небольшое. А проверять правильность собранной комбинации по контрольной сумме записанной в чанке. Все очень просто. Но не тут то было, до какого-то момента все работает отлично, но когда дело доходит до чанков `IDAT`, которые все по 0x80 байт, в то время как размер кусочков нечетный и после какого-то количества возникают коллизии. Собранные данные, содержат недостаточно данных, для того что бы можно было точно знать какой кусок нужно дописать следующим. И таких коллизий было 2 типа:
1. было доступно только размер чанка и его сигнатура
2. был доступен только первый байт размера чанка

И вот в первом случае, было 8 возможных вариантов, а во втором 7, а вместе это 15, что в общем давало не лучшие ожидания на полный перебор и создание всех возможных вариантов файлов. Но я все же написал брутилку и поставил ее генерить файлы. А сам сел дальше разбирать как можно оптимизировать процесс. Посмотрев в каком порядке встречаются коллизии я заметил порядок, что они встречаются по очереди, сперва коллизия первого типа, потом 2-го и т.д.. Т.к. мой брутер генерил не файлы, а правила, по которым собирать файлы, что позволяло самому вручную устанавливать правила. Чем я и занялся, пока брутер работал я решил вручную поиграться с правилами. Открыв картинку сгенерированную без каких либо правил можно было заметить, что небольшая верхняя часть картинки уже собрана правильно и видно макушки фигурных скобок. Отлично, значит если подобрать правильно следующий кусок, то можно будет увидеть еще часть картинки, чем я и занялся. Т.к. было всего 8 вариантов первой коллизии, то перебрать их вручную и посмотреть результаты было несложно. И так я начал менять значение и смотреть результат 0... 1... 2... 3... 4... и тут я начинаю немного унывать, т.к. пока ничего не работает как мне хочется, но я продолжаю 5... 6... 7!!! и как оказалось правильный вариант был последний, заставил меня понервничать :). Ну что ж, схема рабочая, теперь подбираю первое значение для коллизии 2-го типа, тут было легче, т.к. сразу же второе значение дало результат. Воодушевившись отличными результатами я с большим удовольствием продолжил :) И спустя пару минут у меня была картинка с флагом.

**UPD**


Мой скрипт работал отлично на моет ноуте с арчем, на котором он собственно и писался, но вот на макбуке выдавал совсем другой результат, а на виртуалке с кубунтой 3-й и как потом оказалось `glob` очень платформозависимый. Выяснилось что каждая с 3-х систем по своему сортировала файлы. Потому пришлось добавить в скрипт принудительную сортировку и пересчитать правила.

``` python
import sys
import os
from copy import copy
from math import ceil
from glob import glob
from zlib import crc32
from hashlib import sha256
from struct import unpack_from
from itertools import product
from Queue import Queue
from threading import Thread, Lock

chunks = [
    'IHDR',
    'tEXt',
    'PLTE',
    'cHRM',
    'sRGB',
    'iEXt',
    'zEXt',
    'tIME',
    'pHYs',
    'bKGD',
    'sBIT',
    'sPLT',
    'tRNS',
    'IDAT',
    'IEND',
]


class PNGBuilder:
    def __init__(self, data, files, frules, rules):
        self.data = data
        self.files = copy(files)
        self.frules = frules
        self.rules = rules
        self.frules_count = 0
        self.rules_count = 0

    def write_file(self):
        with open('out/%s.png' % sha256(self.data).hexdigest(), 'wb') as f:
            f.write('\x89PNG\r\n\x1a')
            f.write(self.data)
            f.write('\x00\x00\x00\x00IEND\xaeB`\x82')

        if len(self.files) == 1:
            print sha256(self.data).hexdigest()
        else:
            os.remove('./out/%s.png' % sha256(self.data).hexdigest())

    def get_last_chunk(self):
        for i in xrange(len(self.data) - 4, -1, -1):
            if self.data[i:i+4] in chunks:
                chunk_size = unpack_from('>I', self.data, i - 4)[0]
                if len(self.data) - i - chunk_size - 4 - 4 <= 0:
                    return i, chunk_size
                else:
                    break

        n = len(self.data) - i - chunk_size - 4 - 4

        s = '\x00\x00\x00\x80'[n:]
        lc = 0
        for a in self.files:
            if a.startswith(s):
                if lc == self.rules[self.rules_count]:
                    self.rules_count += 1
                    self.data += a
                    self.files.remove(a)
                    return self.get_last_chunk()
                lc += 1

        print 'Can\'t find next chunk'
        sys.exit(2)


    def check_chunk(self, data, offset, size):
        chunk = data[offset:offset + 4 + size]
        checksum = unpack_from('>I', data, offset + 4 + size)[0]
        crc = crc32(chunk) & 0xFFFFFFFF
        return crc == checksum

    def build_chunk(self, offset, size):
        n = int(ceil((size - (len(self.data) - offset) + 4 + 4) / 63.))
        lc = 0
        for a in product(self.files, repeat=n):
            c = self.data + ''.join(a)
            if self.check_chunk(c, offset, size):
                if self.data[-4:] == 'IDAT':
                    if lc == self.frules[self.frules_count]:
                        self.frules_count += 1
                        for i in a:
                            if i in self.files:
                                if i.count('\x00') != 63:
                                    self.files.remove(i)
                        return c
                    lc += 1
                else:
                    for i in a:
                        if i in self.files:
                            if i.count('\x00') != 63:
                                self.files.remove(i)
                    return c
        print 'Can\'t build chunk'
        sys.exit(1)


    def make_file(self):
        while True:
            offset, size = self.get_last_chunk()
            if size == 3:
                # lock.acquire()
                self.write_file()
                # lock.release()
                break
            if len(self.data) - offset < size + 4 + 4:
                self.data = self.build_chunk(offset, size)


class MyThread(Thread):
    def __init__(self, data, files, q):
        super(MyThread, self).__init__()
        self.q = q
        self.data = data
        self.files = files

    def run(self):
        while True:
            frules, rules = self.q.get()
            builder = PNGBuilder(self.data, self.files, frules, rules)
            builder.make_file()
            self.q.task_done()


def get_content(fname):
    with open(fname, 'rb') as f:
        data = f.read()
    return data


first = 'Tatter/8528110b1d24644703a3ae98bd649ee1667f4983'
files = glob('Tatter/*')
# hack to fix OS depended file sorting
files.sort()
files.remove(first)
files = map(get_content, files)

data = get_content(first)

# queue = Queue()
# lock = Lock()

# for i in range(4):
#     worker = MyThread(data, files, queue)
#     worker.setDaemon(True)
#     worker.start()

# for frules in product(range(8), range(7), range(6), range(5), range(4), range(3), range(2), range(1)):
#     for rules in product(range(7), range(6), range(5), range(4), range(3), range(2), range(1)):
#         queue.put((frules, rules))

# queue.join()
# print 'Done'

# flag.png
# my OS depended rules
# frules = (7, 4, 1, 0, 3, 1, 0, 0)
# rules = (1, 2, 1, 3, 1, 0, 0)

# OS independed rules
frules = (7, 1, 2, 1, 2, 2, 0, 0)
rules  = (2, 5, 0, 3, 2, 0, 0)
builder = PNGBuilder(data, files, frules, rules)
builder.make_file()
```

![]({{ site.url }}/image/tatter_flag.png)
