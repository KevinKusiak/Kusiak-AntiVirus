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

size_sig = {}  
p1_sig = []  
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

    size = int(t[0], 16) 

    cs1 = t[1].split(',')  # CS1
    cs1_flag = int(cs1[0].strip(), 16)
    cs1_off = int(cs1[1].strip(), 16)
    cs1_size = int(cs1[2].strip(), 16)
    cs1_crc32 = int(cs1[3].strip(), 16)

    cs2 = t[2].split(',')  # CS2
    cs2_flag = int(cs2[0].strip(), 16)
    cs2_off = int(cs2[1].strip(), 16)
    cs2_size = int(cs2[2].strip(), 16)
    cs2_crc32 = int(cs2[3].strip(), 16)

    name = t[3]

    sig_id = size_sig.get(size, [])
    sig_id.append(len(p1_sig))
    size_sig[size] = sig_id

    p1_sig.append([cs1_flag, cs1_off, cs1_size, cs1_crc32])

    if name in name_sig:  
        name_id = name_sig.index(name)
    else:
        name_id = len(name_sig)
        name_sig.append(name)

    p2_sig.append([cs2_flag, cs2_off, cs2_size, cs2_crc32, name_id])


def save_signature(fname, _id):
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    sname = '%s.s%02d' % (fname, _id)
    t = zlib.compress(marshal.dumps(size_sig))
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
        line = line.strip() 
        
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
        print 'Usage : sigtool_vdb.py [sig text] [id]'
        exit(0)

    if len(sys.argv) == 2:
        sin_fname = sys.argv[1]
        _id = 1
    elif len(sys.argv) == 3:
        sin_fname = sys.argv[1]
        _id = int(sys.argv[2])

    make_signature(sin_fname, _id)