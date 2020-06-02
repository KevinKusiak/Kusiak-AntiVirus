import cgi
import HTMLParser
import csv
import xml.etree.cElementTree as ET
import json
import email

try:
    from backports import lzma
    import yara
    import py7zlib
except ImportError:
    pass

import os
import sys
import types
import hashlib
import urllib
import time
import struct
import datetime
import gzip
import re
import tempfile
from optparse import OptionParser
import kavcore.k2engine
import kavcore.k2const

try:
    import pylzma
except ImportError:
    pass

if os.name == 'nt':
    from ctypes import wintypes

KAV_VERSION = '0.33'
KAV_BUILDDATE = 'Mar 17 2020'
KAV_LASTYEAR = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

g_options = None  
g_delta_time = None  
display_scan_result = {'Prev': {}, 'Next': {}}  
display_update_result = '' 

PLUGIN_ERROR = False 

NOCOLOR = False 


if os.name == 'nt':
    FOREGROUND_BLACK = 0x0000
    FOREGROUND_BLUE = 0x0001
    FOREGROUND_GREEN = 0x0002
    FOREGROUND_CYAN = 0x0003
    FOREGROUND_RED = 0x0004
    FOREGROUND_MAGENTA = 0x0005
    FOREGROUND_YELLOW = 0x0006
    FOREGROUND_GREY = 0x0007
    FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

    from ctypes import windll, Structure, c_short, c_ushort, byref

    SHORT = c_short
    WORD = c_ushort


    class Coord(Structure):
      _fields_ = [
        ("X", SHORT),
        ("Y", SHORT)]


    class SmallRect(Structure):
        _fields_ = [
            ("Left", SHORT),
            ("Top", SHORT),
            ("Right", SHORT),
            ("Bottom", SHORT)]


    class ConsoleScreenBufferInfo(Structure):
        _fields_ = [
            ("dwSize", Coord),
            ("dwCursorPosition", Coord),
            ("wAttributes", WORD),
            ("srWindow", SmallRect),
            ("dwMaximumWindowSize", Coord)]

    # winbase.h
    STD_INPUT_HANDLE = -10
    STD_OUTPUT_HANDLE = -11
    STD_ERROR_HANDLE = -12

    stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
    GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo


    def get_text_attr():
        csbi = ConsoleScreenBufferInfo()
        GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
        return csbi.wAttributes


    def set_text_attr(color):
        SetConsoleTextAttribute(stdout_handle, color)


    def cprint(msg, color):
        try:
            if not NOCOLOR:  
                default_colors = get_text_attr()
                default_bg = default_colors & 0x00F0

                set_text_attr(color | default_bg)
                sys.stdout.write(msg)
                set_text_attr(default_colors)
            else:  
                sys.stdout.write(msg)
                sys.stdout.flush()
        except IOError:
            pass
else:
    FOREGROUND_BLACK = 0x0000
    FOREGROUND_RED = 0x0001
    FOREGROUND_GREEN = 0x0002
    FOREGROUND_YELLOW = 0x0003
    FOREGROUND_BLUE = 0x0004
    FOREGROUND_MAGENTA = 0x0005
    FOREGROUND_CYAN = 0x0006
    FOREGROUND_GREY = 0x0007
    FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

    COLOR_RESET = '\033[0m'  # Text Reset

    def cprint(msg, color):
        if color & FOREGROUND_INTENSITY == FOREGROUND_INTENSITY:
            color &= 0x7
            str_color = '\033[0;%2Xm' % (0x90 + color)
        else:
            str_color = '\033[0;%2Xm' % (0x30 + color)
        sys.stdout.write(str_color + msg + COLOR_RESET)
        sys.stdout.flush()


def print_error(msg):
    cprint('Error: ', FOREGROUND_RED | FOREGROUND_INTENSITY)
    print (msg)

def getch():
    if os.name == 'nt':
        import msvcrt

        return msvcrt.getch()
    else:
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch

def create_folder(path):
    if os.path.exists(path) is False:
        t_dir = path

        while 1:
            if os.path.exists(t_dir) is False:
                t_dir, tmp = os.path.split(t_dir)
            else:
                break


        makedir = path.replace(t_dir, '')
        mkdir_list = makedir.split(os.sep)

        for m in mkdir_list:
            if len(m) != 0:
                t_dir += (os.sep + m)
                os.mkdir(t_dir)

        return True
    else:
        return False

def log_print(msg, file_mode='at'):
    global g_options

    if g_options != 'NONE_OPTION':
        log_mode = False
        log_fname = 'k2.log'  

        if g_options.log_filename:
            log_fname = g_options.log_filename
            log_mode = True

        if g_options.opt_log:
            log_mode = True

        if log_mode:
            with open(log_fname, file_mode) as fp:
                fp.write(msg)


def print_k2logo():
    logo = '''AcuAngle Security Anti-Virus  (for %s) Ver %s (%s)
Copyright (C) 2020-%s Kevin Wesley Kusiak. All rights reserved.
'''

    s = logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    cprint(s, FOREGROUND_CYAN | FOREGROUND_INTENSITY)

class OptionParsingError(RuntimeError):
    def __init__(self, msg):
        self.msg = msg


class OptionParsingExit(Exception):
    def __init__(self, status, msg):
        self.msg = msg
        self.status = status


class ModifiedOptionParser(OptionParser):
    def error(self, msg):
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None):
        raise OptionParsingExit(status, msg)

def define_options():
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files",
                      action="store_true", dest="opt_files",
                      default=True)
    parser.add_option("-r", "--arc",
                      action="store_true", dest="opt_arc",
                      default=False)
    parser.add_option("-G",
                      action="store_true", dest="opt_log",
                      default=False)
    parser.add_option("", "--log",
                      metavar="FILE", dest="log_filename")
    parser.add_option("-I", "--list",
                      action="store_true", dest="opt_list",
                      default=False)
    parser.add_option("-e", "--app",
                      action="store_true", dest="opt_app",
                      default=False)
    parser.add_option("-F", "--infp",
                      metavar="PATH", dest="infp_path")
    parser.add_option("", "--qname", 
                      action="store_true", dest="opt_qname",
                      default=False)
    parser.add_option("", "--qhash", 
                      action="store_true", dest="opt_qhash",
                      default=False)
    parser.add_option("-R", "--nor",
                      action="store_true", dest="opt_nor",
                      default=False)
    parser.add_option("-V", "--vlist",
                      action="store_true", dest="opt_vlist",
                      default=False)
    parser.add_option("-p", "--prompt",
                      action="store_true", dest="opt_prompt",
                      default=False)
    parser.add_option("-d", "--dis",
                      action="store_true", dest="opt_dis",
                      default=False)
    parser.add_option("-l", "--del",
                      action="store_true", dest="opt_del",
                      default=False)
    parser.add_option("", "--no-color",
                      action="store_true", dest="opt_nocolor",
                      default=False)
    parser.add_option("", "--move",
                      action="store_true", dest="opt_move",
                      default=False)
    parser.add_option("", "--copy",
                      action="store_true", dest="opt_copy",
                      default=False)
    parser.add_option("", "--update",
                      action="store_true", dest="opt_update",
                      default=False)
    parser.add_option("", "--verbose",
                      action="store_true", dest="opt_verbose",
                      default=False)
    parser.add_option("", "--sigtool",
                      action="store_true", dest="opt_sigtool",
                      default=False)
    parser.add_option("", "--debug",
                      action="store_true", dest="opt_debug",
                      default=False)
    parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)


    parser.add_option("", "--feature",
                      type="int", dest="opt_feature",
                      default=0xffffffff)

    return parser

def parser_options():
    parser = define_options() 

    if len(sys.argv) < 2:
        return 'NONE_OPTION', None
    else:
        try:
            (options, args) = parser.parse_args()
            if len(args) == 0:
                return options, None
        except OptionParsingError, e: 
            return 'ILLEGAL_OPTION', e.msg
        except OptionParsingExit, e:
            return 'ILLEGAL_OPTION', e.msg

        return options, args

def print_usage():
    print '\nUsage: k2.py path[s] [options]'

def print_options():
    options_string = '''Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -G,  --log=file        create log file
        -I,  --list            display all files
        -e,  --app             append to log file
        -F,  --infp=path       set infected quarantine folder
        -R,  --nor             do not recurse into folders
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
             --no-color        don't print with color
             --move            move infected files in quarantine folder
             --copy            copy infected files in quarantine folder
             --qname           quarantine by name of malware 
             --qhash           quarantine by sha256 hash of malware
             --update          update
             --verbose         enabling verbose mode (only Developer Edition)
             --sigtool         make files for malware signatures
        -?,  --help            this help
                               * = default option'''

    print options_string


def update_kicomav(path):
    print

    try:
        url = 'https://raw.githubusercontent.com/hanul93/kicomav-db/master/update_v3/'  

        down_list = get_download_list(url, path)
        is_k2_exe_update = 'k2.exe' in down_list

        while len(down_list) != 0:
            filename = down_list.pop(0)

            if filename != 'k2.exe':
                download_file(url, filename, path, gz=True, fnhook=hook)

        if os.name == 'nt' and is_k2_exe_update:
            k2temp_path = download_file_k2(url, 'k2.exe', path, gz=True, fnhook=hook)

        os.remove(os.path.join(path, 'update.cfg'))

        cprint('\n[', FOREGROUND_GREY)
        cprint('Update complete', FOREGROUND_GREEN)
        cprint(']\n', FOREGROUND_GREY)

        if os.name == 'nt' and is_k2_exe_update:
            os.spawnv(os.P_NOWAIT, k2temp_path, (k2temp_path, 'k2', path))
    except KeyboardInterrupt:
        cprint('\n[', FOREGROUND_GREY)
        cprint('Update Stop', FOREGROUND_GREY | FOREGROUND_INTENSITY)
        cprint(']\n', FOREGROUND_GREY)
    except:
        cprint('\n[', FOREGROUND_GREY)
        cprint('Update failed', FOREGROUND_RED | FOREGROUND_INTENSITY)
        cprint(']\n', FOREGROUND_GREY)


def hook(blocknumber, blocksize, totalsize):
    cprint('.', FOREGROUND_GREY)


def download_file(url, filename, path, gz=False, fnhook=None):
    rurl = url

    rurl += filename.replace('\\', '/')
    if gz:
        rurl += '.gz'

    pwd = os.path.join(path, filename)

    if gz:
        pwd += '.gz'

    if fnhook is not None:
        cprint(filename + ' ', FOREGROUND_GREY)

    urllib.urlretrieve(rurl, pwd, fnhook)

    if gz:
        data = gzip.open(pwd, 'rb').read()
        fname = os.path.join(path, filename)
        open(fname, 'wb').write(data)
        os.remove(pwd)  

    if fnhook is not None:
        cprint(' update\n', FOREGROUND_GREEN)


def download_file_k2(url, filename, path, gz=False, fnhook=None):
    rurl = url

    rurl += filename.replace('\\', '/')
    if gz:
        rurl += '.gz'

    pwd = os.path.join(path, filename)
    if gz:
        pwd += '.gz'

    if fnhook is not None:
        cprint(filename + ' ', FOREGROUND_GREY)

    urllib.urlretrieve(rurl, pwd, fnhook)

    if gz:
        data = gzip.open(pwd, 'rb').read()
        fname = tempfile.mktemp(prefix='ktmp') + '.exe'
        open(fname, 'wb').write(data)
        os.remove(pwd) 

    if fnhook is not None:
        cprint(' update\n', FOREGROUND_GREEN)

    return fname


def get_download_list(url, path):
    down_list = []

    pwd = path

    try:
        download_file(url, 'update.cfg', pwd)

        buf = open(os.path.join(pwd, 'update.cfg'), 'r').read()
        p_lists = re.compile(r'([A-Fa-f0-9]{40}) (.+)')
        lines = p_lists.findall(buf)

        for line in lines:
            fhash = line[0]
            fname = line[1]

            if chek_need_update(os.path.join(pwd, fname), fhash) == 1:
                down_list.append(fname)
    except:
        pass

    return down_list


def chek_need_update(file, hash):
    try:
        fp = open(file, 'rb')
        data = fp.read()
        fp.close()

        s = hashlib.sha1()
        s.update(data)
        if s.hexdigest() == hash:
            return 0  
    except IOError:
        pass

    return 1  

def listvirus_callback(plugin_name, vnames):
    for vname in vnames:
        print '%-50s [%s.kmd]' % (vname, plugin_name)

def get_terminal_sizex():
    default_sizex = 80

    if os.name == 'nt':
        try:
            from ctypes import windll, create_string_buffer
            h = windll.kernel32.GetStdHandle(-12)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                (bufx, bufy, curx, cury, wattr,
                 left, top, right, bottom,
                 maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                sizex = right - left + 1
                return sizex
        except:
            pass
    else:
        def ioctl_GWINSZ(fd):
            try:
                import fcntl
                import termios
                cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
                return cr
            except:
                pass

        cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
        if not cr:
            try:
                fd = os.open(os.ctermid(), os.O_RDONLY)
                cr = ioctl_GWINSZ(fd)
                os.close(fd)
            except:
                pass
        if not cr:
            try:
                cr = (os.environ['LINES'], os.environ['COLUMNS'])
            except:
                return default_sizex
        return int(cr[1])  

    return default_sizex  


def convert_display_filename(real_filename):
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    if isinstance(real_filename, types.UnicodeType):
        display_filename = real_filename.encode(sys.stdout.encoding, 'replace')
    else:
        display_filename = unicode(real_filename, fsencoding).encode(sys.stdout.encoding, 'replace')

    if display_filename[0] == '/' or display_filename[0] == '\\':
        return display_filename[1:]
    else:
        return display_filename

def display_line(filename, message, message_color):
    max_sizex = get_terminal_sizex() - 1
    filename += ' '
    filename = convert_display_filename(filename)
    len_fname = len(filename)
    len_msg = len(message)

    if len_fname + 1 + len_msg < max_sizex:
        fname = '%s' % filename
    else:
        able_size = max_sizex - len_msg
        able_size -= 5  # ...
        min_size = able_size / 2
        if able_size % 2 == 0:
            fname1 = filename[:min_size-1]
        else:
            fname1 = filename[:min_size]
        fname2 = filename[len_fname - min_size:]

        fname = '%s ... %s' % (fname1, fname2)

    cprint(fname + ' ', FOREGROUND_GREY)
    cprint(message + '\n', message_color)

def scan_callback(ret_value):
    global g_options
    global display_scan_result

    import kernel

    fs = ret_value['file_struct']

    if len(fs.get_additional_filename()) != 0:
        f2 = convert_display_filename(fs.get_additional_filename())
        disp_name = '%s (%s)' % (fs.get_master_filename(), f2)
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if ret_value['result']:
        if ret_value['scan_state'] == kernel.INFECTED:
            state = 'infected'
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
        elif ret_value['scan_state'] == kernel.SUSPECT:
            state = 'suspect'
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
        elif ret_value['scan_state'] == kernel.WARNING:
            state = 'warning'
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
        elif ret_value['scan_state'] == kernel.IDENTIFIED:
            state = 'identified'
            message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
        else:
            state = 'unknown'
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

        vname = ret_value['virus_name']
        message = '%s : %s' % (state, vname)
    else:
        if ret_value['scan_state'] == kernel.ERROR:
            message = ret_value['virus_name']
            message_color = FOREGROUND_CYAN | FOREGROUND_INTENSITY
        else:
            message = 'ok'
            message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    if message == 'ok':
        d_prev = display_scan_result.get('Prev', {})
        if d_prev == {}:
            d_prev['disp_name'] = disp_name
            d_prev['message'] = message
            d_prev['message_color'] = message_color
        elif d_prev['disp_name'] != disp_name:
            d_next = display_scan_result.get('Next', {})
            if d_next == {}:
                d_next['disp_name'] = disp_name
                d_next['message'] = message
                d_next['message_color'] = message_color
            elif d_next['disp_name'] != disp_name:
                if d_next['disp_name'] != disp_name:
                    display_line(d_prev['disp_name'], d_prev['message'], d_prev['message_color'])
                    log_print('%s\t%s\n' % (d_prev['disp_name'], d_prev['message']))

                    d_prev['disp_name'] = d_next['disp_name']
                    d_prev['message'] = d_next['message']
                    d_prev['message_color'] = d_next['message_color']

                    d_next['disp_name'] = disp_name
                    d_next['message'] = message
                    d_next['message_color'] = message_color
                else:  
                    pass
    else:  
        print_display_scan_result(disp_name, message, message_color)

    if g_options.opt_move is False and g_options.opt_prompt: 
        while True and ret_value['result']:
            if ret_value['scan_state'] == kernel.INFECTED:
                msg = 'Disinfect/Delete/Ignore/Quit? (d/l/i/q) : '
            else:
                msg = 'Delete/Ignore/Quit? (l/i/q) : '

            cprint(msg, FOREGROUND_CYAN | FOREGROUND_INTENSITY)
            log_print(msg)

            ch = getch().lower()
            print ch
            log_print(ch + '\n')

            if ret_value['scan_state'] == kernel.INFECTED and ch == 'd':
                return kavcore.k2const.K2_ACTION_DISINFECT
            elif ch == 'l':
                return kavcore.k2const.K2_ACTION_DELETE
            elif ch == 'i':
                return kavcore.k2const.K2_ACTION_IGNORE
            elif ch == 'q':
                return kavcore.k2const.K2_ACTION_QUIT
    elif g_options.opt_dis:  
        return kavcore.k2const.K2_ACTION_DISINFECT
    elif g_options.opt_del: 
        return kavcore.k2const.K2_ACTION_DELETE

    return kavcore.k2const.K2_ACTION_IGNORE


def print_display_scan_result(disp_name, message, message_color):
    global display_scan_result  

    d_prev = display_scan_result.get('Prev', {})
    if d_prev != {} and d_prev['disp_name'] != disp_name:
        display_line(d_prev['disp_name'], d_prev['message'], d_prev['message_color'])
        log_print('%s\t%s\n' % (d_prev['disp_name'], d_prev['message']))
        display_scan_result['Prev'] = {}  

    d_next = display_scan_result.get('Next', {})
    if d_next != {} and d_next['disp_name'] != disp_name:
        display_line(d_next['disp_name'], d_next['message'], d_next['message_color'])
        log_print('%s\t%s\n' % (d_next['disp_name'], d_next['message']))
        display_scan_result['Next'] = {}  

    if disp_name:
        display_line(disp_name, message, message_color)
        log_print('%s\t%s\n' % (disp_name, message))

def disinfect_callback(ret_value, action_type):
    fs = ret_value['file_struct']
    message = ''

    if len(fs.get_additional_filename()) != 0:
        disp_name = '%s (%s)' % (fs.get_master_filename(), fs.get_additional_filename())
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if fs.is_modify():  
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfected'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deleted'

        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfection failed'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deletion failed'

        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)
    log_print('%s\t%s\n' % (disp_name, message))

def update_callback(ret_file_info, is_success):
    global display_update_result

    print_display_scan_result(None, None, None)

    if ret_file_info.is_modify(): 
        if len(ret_file_info.get_additional_filename()) != 0:
            disp_name = '%s (%s)' % (ret_file_info.get_master_filename(), ret_file_info.get_additional_filename())
        else:
            disp_name = '%s' % (ret_file_info.get_master_filename())

        if is_success:
            if os.path.exists(ret_file_info.get_filename()):
                message = 'updated'
            else:
                message = 'deleted'

            message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
        else:
            message = 'update failed'
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

        if display_update_result != disp_name:  
            display_line(disp_name, message, message_color)
            log_print('%s\t%s\n' % (disp_name, message))

            display_update_result = disp_name

def quarantine_callback(filename, is_success, q_type):
    import kernel

    q_message = {
        kavcore.k2const.K2_QUARANTINE_MOVE: ['quarantined', 'quarantine failed'],
        kavcore.k2const.K2_QUARANTINE_COPY: ['copied', 'copy failed'],
    }

    msg = q_message[q_type]

    disp_name = filename

    if is_success:
        message = msg[0]  
        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:
        message = msg[1]  
        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)
    log_print('%s\t%s\n' % (disp_name, message))

def import_error_callback(module_name):
    global PLUGIN_ERROR
    global g_options

    if g_options.opt_debug:
        if not PLUGIN_ERROR:
            PLUGIN_ERROR = True
            print
            print_error('Invalid plugin: \'%s\'' % module_name)

def print_result(result):
    global g_options
    global g_delta_time

    print
    print

    cprint('Results:\n', FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Folders           :%d\n' % result['Folders'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Files             :%d\n' % result['Files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Packed            :%d\n' % result['Packed'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Infected files    :%d\n' % result['Infected_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Suspect files     :%d\n' % result['Suspect_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Warnings          :%d\n' % result['Warnings'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Identified viruses:%d\n' % result['Identified_viruses'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    if result['Disinfected_files']:
        cprint('Disinfected files :%d\n' % result['Disinfected_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    elif result['Deleted_files']:
        cprint('Deleted files     :%d\n' % result['Deleted_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('I/O errors        :%d\n' % result['IO_errors'], FOREGROUND_GREY | FOREGROUND_INTENSITY)

    t = str(g_delta_time).split(':')
    t_h = int(float(t[0]))
    t_m = int(float(t[1]))
    t_s = int(float(t[2]))
    cprint('Scan time         :%02d:%02d:%02d\n' % (t_h, t_m, t_s), FOREGROUND_GREY | FOREGROUND_INTENSITY)

    print

def main():
    global NOCOLOR
    global g_options

    options, args = parser_options()
    g_options = options  

    if os.name == 'nt' and not isinstance(options, types.StringType):
        if options.opt_nocolor:
            NOCOLOR = True

    print_k2logo()

    if options == 'NONE_OPTION':  
        print_usage()
        print_options()
        return 0
    elif options == 'ILLEGAL_OPTION': 
        print_usage()
        print 'Error: %s' % args  
        return 0

    k2_pwd = os.path.abspath(os.path.split(sys.argv[0])[0])

    if options.opt_help or not args:
        if options.opt_update:
            update_kicomav(k2_pwd)
            return 0

        if not options.opt_vlist:  
            print_usage()
            print_options()
            return 0

    if g_options.opt_app is False:
        log_print('#\n# KicomAV scan report\n#\n', 'wt')  
    else:
        log_print('\n#\n# KicomAV scan report\n#\n')

    log_print('# Time: %s\n' % time.ctime())

    log_print('# Command line: ')
    for argv in sys.argv[1:]:
        log_print(argv + ' ')
    log_print('\n')

    logo = 'KICOM Anti-Virus II (for %s) Ver %s (%s)' % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE)
    log_print('# %s\n' % logo)

    if options.opt_update:
        update_kicomav()

    if options.infp_path:
        path = os.path.abspath(options.infp_path)
        path = os.path.normcase(path)
        create_folder(path)
        options.infp_path = path

    k2 = kavcore.k2engine.Engine() 

    plugins_path = os.path.join(k2_pwd, 'plugins')
    if not k2.set_plugins(plugins_path, import_error_callback):
        print
        print_error('KICOM Anti-Virus Engine set_plugins')
        return 0

    kav = k2.create_instance() 
    if not kav:
        print
        print_error('KICOM Anti-Virus Engine create_instance')
        return 0

    kav.set_options(options) 

    if not kav.init(import_error_callback):  
        print
        print_error('KICOM Anti-Virus Engine init')
        return 0

    if options.opt_debug:
        if PLUGIN_ERROR: 
            print

    c = kav.get_version()
    msg = '\rLast updated %s UTC\n' % c.ctime()
    cprint(msg, FOREGROUND_GREY)

    num_sig = format(kav.get_signum(), ',')
    msg = 'Signature number: %s\n\n' % num_sig
    cprint(msg, FOREGROUND_GREY)

    log_print('# Signature number: %s\n' % num_sig)
    log_print('#\n\n')  

    if options.opt_vlist is True:  
        kav.listvirus(listvirus_callback)
    else:
        if args:
            kav.set_result()  

            start_time = datetime.datetime.now()

            for scan_path in args:  
                scan_path = os.path.abspath(scan_path)

                if os.path.exists(scan_path): 
                    kav.scan(scan_path, scan_callback, disinfect_callback, update_callback, quarantine_callback)
                else:
                    
                    print_display_scan_result(None, None, None)

                    print_error('Invalid path: \'%s\'' % scan_path)

            end_time = datetime.datetime.now()

            global g_delta_time
            g_delta_time = end_time - start_time

            print_display_scan_result(None, None, None)

            ret = kav.get_result()
            print_result(ret)

    kav.uninit()


if __name__ == '__main__':
    main()