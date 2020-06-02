# -*- coding:utf-8 -*-
# normfile.py [sigtool.log]


import sys
import re
import hashlib


p_http = re.compile(r'https?://')
p_script_cmt1 = re.compile(r'//.*|/\*[\d\D]*?\*/')
p_script_cmt2 = re.compile(r'(#|\bREM\b).*', re.IGNORECASE)
p_space = re.compile(r'\s')

p_vba = re.compile(r'^\s*Attribute\s+VB_Name.+|^\s*Attribute\s+.+VB_Invoke_Func.+|\s+_\r?\n', re.IGNORECASE|re.MULTILINE)
p_vba_cmt = re.compile(r'(\'|\bREM\b).*', re.IGNORECASE)

def normfile(fname, ftype):
    buf = open(fname, 'rb').read()  

    if ftype.find('HTML/Script') >= 0 or ftype.find('HTML/IFrame') >= 0:
        buf = p_http.sub('', buf)  
        buf = p_script_cmt1.sub('', buf)  
        buf = p_script_cmt2.sub('', buf)  
        buf = p_space.sub('', buf)  
        buf = buf.lower()  
    elif ftype.find('VBA/') >= 0 and buf.find('Attribute VB_Name') >= 0:
        buf = p_vba_cmt.sub('', buf)  
        buf = p_vba.sub('', buf) 
        buf = p_space.sub('', buf)  
        buf = buf.lower()  
    elif ftype.find('Attached') >= 0:
        pass
    else:
        print 'NOT Support : %s' % ftype
        return

    new_fname = 'm_'+fname
    open(new_fname, 'wb').write(buf)

    fsize = len(buf)
    fmd5 = hashlib.md5(buf).hexdigest()

    msg = '%d:%s:Malware_Name  # %s, %s\n' % (fsize, fmd5, new_fname, ftype)
    open('sigtool_md5.log', 'at').write(msg)

def main(log_fname):
    fp = open(log_fname)
    while True:
        line = fp.readline()
        if not line:
            break
        line = line.strip()

        f = line.split(':')

        fname = f[0].strip()
        ftype = f[1].strip()
        print fname

        normfile(fname, ftype)  
    fp.close()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage : normfile.py [sigtool.log]'
        exit(0)

    main(sys.argv[1])