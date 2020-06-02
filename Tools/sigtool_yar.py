# -*- coding:utf-8 -*-

import re
import sys
import os
import struct
import yara
import zlib
import cPickle


s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'kavcore'

sys.path.append(s)

import k2timelib


re_rule = r'rule\s+\w+'


def save_file(fname, data):
    fp = open(fname, 'wb')
    fp.write(data)
    fp.close()


def make_signature(fname):
    p_rule = re.compile(re_rule)

    buf = open(fname, 'rb').read()
    sig_num = len(p_rule.findall(buf))

    c = yara.compile(fname)
    c.save(fname + '.yc')

    buf = open(fname + '.yc', 'rb').read()
    os.remove(fname + '.yc')

    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    name = os.path.splitext(fname)[0]
    sname = '%s.y01' % name
    t = zlib.compress(buf)
    t = 'KAVS' + struct.pack('<L', sig_num) + val_date + val_time + t
    save_file(sname, t)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage : sigtool_yar.py [sig text]'
        exit(0)

    sin_fname = sys.argv[1]

    make_signature(sin_fname)