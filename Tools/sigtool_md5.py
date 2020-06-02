# -*- coding:utf-8 -*-


import re
import sys
import os
import struct
import marshal
import zlib

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'kavcore'

sys.path.append(s)

import k2timelib


MAX_COUNT = 100000

re_comment = r'#.*'

size_sig = []  
p1_sig = {}  
p2_sig = []  
name_sig = []  


def printProgress(_off, _all):
    if _off != 0:
        percent = (_off * 100.) / _all

        s_num = int(percent / 5)
        space_num = 20 - s_num

        sys.stdout.write('[*] Download : [')
        sys.stdout.write('#' * s_num)
        sys.stdout.write(' ' * space_num)
        sys.stdout.write('] ')
        sys.stdout.write('%3d%%  (%d/%d)\r' % (int(percent), _off, _all))


def add_signature(line):
    t = line.split(':')

    size = int(t[0])  # size
    fmd5 = t[1].decode('hex')  
    name = t[2]

    size_sig.append(size)

    p1 = fmd5[:6]  # 6Byte
    p2 = fmd5[6:]  # 10Byte


    p2_id = len(p2_sig)

    if p1 in p1_sig:
        p1_sig[p1].append(p2_id)
    else:
        p1_sig[p1] = [p2_id]

    if name in name_sig:  
        name_id = name_sig.index(name)
    else:
        name_id = len(name_sig)
        name_sig.append(name)

    p2_sig.append((p2, name_id))


def save_signature(fname, _id):
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    sname = '%s.s%02d' % (fname, _id)
    t = zlib.compress(marshal.dumps(set(size_sig)))  
    t = 'KAVS' + struct.pack('<L', len(size_sig)) + val_date + val_time + t
    save_file(sname, t)

    sname = '%s.i%02d' % (fname, _id)
    t = zlib.compress(marshal.dumps(p1_sig))
    t = 'KAVS' + struct.pack('<L', len(p1_sig)) + val_date + val_time + t
    save_file(sname, t)

    sname = '%s.c%02d' % (fname, _id)
    t = zlib.compress(marshal.dumps(p2_sig))
    t = 'KAVS' + struct.pack('<L', len(p2_sig)) + val_date + val_time + t
    save_file(sname, t)

    sname = '%s.n%02d' % (fname, _id)
    t = zlib.compress(marshal.dumps(name_sig))
    t = 'KAVS' + struct.pack('<L', len(name_sig)) + val_date + val_time + t
    save_file(sname, t)


def save_file(fname, data):
    fp = open(fname, 'wb')
    fp.write(data)
    fp.close()


def save_sig_file(fname, _id):
    t = os.path.abspath(fname)
    _, t = os.path.split(t)
    name = os.path.splitext(t)[0]
    save_signature(name, _id)

    global size_sig
    global p1_sig
    global p2_sig
    global name_sig

    size_sig = []  
    p1_sig = {}  
    p2_sig = []  
    name_sig = []  

def make_signature(fname, _id):
    fp = open(fname, 'rb')

    idx = 0

    while True:
        line = fp.readline()
        if not line:
            break

        line = re.sub(re_comment, '', line)
        line = line.strip()  # re.sub(r'\s', '', line)

        if len(line) == 0:
            continue 

        add_signature(line)

        idx += 1
        printProgress(idx, MAX_COUNT)

        if idx >= MAX_COUNT:
            print '[*] %s : %d' % (fname, _id)
            save_sig_file(fname, _id)
            idx = 0
            _id += 1

    fp.close()

    save_sig_file(fname, _id)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage : sigtool_md5.py [sig text] [id]'
        exit(0)

    if len(sys.argv) == 2:
        sin_fname = sys.argv[1]
        _id = 1
    elif len(sys.argv) == 3:
        sin_fname = sys.argv[1]
        _id = int(sys.argv[2])

    make_signature(sin_fname, _id)