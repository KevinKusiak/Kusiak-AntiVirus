import os
import imp
import StringIO
import datetime
import types
import mmap
import glob
import re
import shutil
import struct
import zipfile
import hashlib

import k2timelib
import k2kmdfile
import k2rsa
import k2file
import k2const

class EngineKnownError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Engine:
    def __init__(self, verbose=False):
        self.verbose = verbose  

        self.plugins_path = None 
        self.temp_path = None  
        self.kmdfiles = []  
        self.kmd_modules = []  

        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

        k2file.K2Tempfile().removetempdir()

        self.__set_temppath()  

    def __del__(self):
        self.temp_path.removetempdir()

        try:  
            shutil.rmtree(self.temp_path.temp_path)
        except OSError:
            pass

    def set_plugins(self, plugins_path, callback_fn=None):
        self.plugins_path = plugins_path

        if k2const.K2DEBUG:
            pu = None
            ret = self.__get_kmd_list(os.path.join(plugins_path, 'kicom.lst'), pu)
        else:
            pu = k2rsa.read_key(os.path.join(plugins_path, 'key.pkr'))
            if not pu:
                return False

            ret = self.__get_kmd_list(os.path.join(plugins_path, 'kicom.kmd'), pu)

        if not ret: 
            return False

        if self.verbose:
            print '[*] kicom.%s :' % ('lst' if k2const.K2DEBUG else 'kmd')
            print '   ', self.kmdfiles

        for kmd_name in self.kmdfiles:
            kmd_path = os.path.join(plugins_path, kmd_name)
            try:
                name = kmd_name.split('.')[0]
                if k2const.K2DEBUG:
                    k = None
                    module = imp.load_source(name, os.path.splitext(kmd_path)[0] + '.py')
                    try:
                        os.remove(os.path.splitext(kmd_path)[0] + '.pyc')
                    except OSError:
                        pass
                else:
                    k = k2kmdfile.KMD(kmd_path, pu)  
                    data = k.body
                    module = k2kmdfile.load(name, data)

                if module:  
                    self.kmd_modules.append(module)
                    self.__get_last_kmd_build_time(k)
                else:  
                    if isinstance(callback_fn, types.FunctionType):
                        callback_fn(name)
            except IOError:
                pass
            except k2kmdfile.KMDFormatError:  
                pass

        fl = glob.glob1(plugins_path, '*.n??')
        for fname in fl:
            try:
                fname = os.path.join(plugins_path, fname)
                buf = open(fname, 'rb').read(12)
                if buf[0:4] == 'KAVS':
                    sdate = k2timelib.convert_date(struct.unpack('<H', buf[8:10])[0])
                    stime = k2timelib.convert_time(struct.unpack('<H', buf[10:12])[0])

                    t_datetime = datetime.datetime(sdate[0], sdate[1], sdate[2], stime[0], stime[1], stime[2])

                    if self.max_datetime < t_datetime:
                        self.max_datetime = t_datetime
            except IOError:
                pass

        if self.verbose:
            print '[*] kmd_modules :'
            print '   ', self.kmd_modules
            print '[*] Last updated %s UTC' % self.max_datetime.ctime()

        return True

    def __set_temppath(self):
        self.temp_path = k2file.K2Tempfile()

    def create_instance(self):
        ei = EngineInstance(self.plugins_path, self.temp_path, self.max_datetime, self.verbose)
        if ei.create(self.kmd_modules):
            return ei
        else:
            return None

    def __get_last_kmd_build_time(self, kmd_info):
        if k2const.K2DEBUG:
            t_datetime = datetime.datetime.utcnow()
        else:
            d_y, d_m, d_d = kmd_info.date
            t_h, t_m, t_s = kmd_info.time

            t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

        if self.max_datetime < t_datetime:
            self.max_datetime = t_datetime

    def __get_kmd_list(self, kicom_kmd_file, pu):
        kmdfiles = []  

        if k2const.K2DEBUG:  
            lst_data = open(kicom_kmd_file, 'rb').read()
        else:
            k = k2kmdfile.KMD(kicom_kmd_file, pu)  
            lst_data = k.body

        if lst_data:  
            msg = StringIO.StringIO(lst_data)

            while True:
                line = msg.readline().strip()

                if not line:  
                    break
                elif line.find('.kmd') != -1:  
                    kmdfiles.append(line)  
                else:  
                    continue

        if len(kmdfiles):  
            self.kmdfiles = kmdfiles
            return True
        else:  
            return False


class EngineInstance:
    def __init__(self, plugins_path, temp_path, max_datetime, verbose=False):
        self.verbose = verbose  

        self.plugins_path = plugins_path 
        self.temp_path = temp_path  
        self.max_datetime = max_datetime 

        self.options = {}  
        self.set_options() 

        self.kavmain_inst = []  

        self.update_info = []  

        self.result = {}
        self.identified_virus = set()  
        self.set_result()  

        self.quarantine_name = {}  

        self.disinfect_callback_fn = None
        self.update_callback_fn = None 
        self.quarantine_callback_fn = None  

        self.disable_path = re.compile(r'/<\w+>')

    def create(self, kmd_modules):  
        for mod in kmd_modules:
            try:
                t = mod.KavMain() 
                self.kavmain_inst.append(t)
            except AttributeError:  
                continue

        if len(self.kavmain_inst):  
            if self.verbose:
                print '[*] Count of KavMain : %d' % (len(self.kavmain_inst))
            return True
        else:
            return False

    def init(self, callback_fn=None):
        t_kavmain_inst = []  

        if self.verbose:
            print '[*] KavMain.init() :'

        for inst in self.kavmain_inst:
            try:
                if k2const.K2DEBUG:
                    ret = inst.init(self.plugins_path, self.options['opt_verbose'])
                else:
                    ret = inst.init(self.plugins_path, False)

                if not ret: 
                    t_kavmain_inst.append(inst)

                    if self.verbose:
                        print '    [-] %s.init() : %d' % (inst.__module__, ret)
                else:  
                    if isinstance(callback_fn, types.FunctionType):
                        callback_fn(inst.__module__)
            except AttributeError:
                continue

        self.kavmain_inst = t_kavmain_inst  

        if len(self.kavmain_inst):  
            if self.verbose:
                print '[*] Count of KavMain.init() : %d' % (len(self.kavmain_inst))
            return True
        else:
            return False

    def uninit(self):
        if self.verbose:
            print '[*] KavMain.uninit() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.uninit()
                if self.verbose:
                    print '    [-] %s.uninit() : %d' % (inst.__module__, ret)
            except AttributeError:
                continue

    def getinfo(self):
        ginfo = []  

        if self.verbose:
            print '[*] KavMain.getinfo() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()
                ginfo.append(ret)

                if self.verbose:
                    print '    [-] %s.getinfo() :' % inst.__module__
                    for key in ret.keys():
                        print '        - %-10s : %s' % (key, ret[key])
            except AttributeError:
                continue

        return ginfo

    def listvirus(self, *callback):
        vlist = []  

        argc = len(callback)  

        if argc == 0:  
            cb_fn = None
        elif argc == 1:  
            cb_fn = callback[0]
        else: 
            return []

        if self.verbose:
            print '[*] KavMain.listvirus() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.listvirus()

                if isinstance(cb_fn, types.FunctionType):
                    cb_fn(inst.__module__, ret)
                else:  
                    vlist += ret

                if self.verbose:
                    print '    [-] %s.listvirus() :' % inst.__module__
                    for vname in ret:
                        print '        - %s' % vname
            except AttributeError:
                continue

        return vlist

    def scan(self, filename, *callback):
        import kernel

        self.update_info = []
        scan_callback_fn = None  

        move_master_file = False 
        t_master_file = ''  

        ret_value = {
            'filename': '',  
            'result': False,  
            'virus_name': '',  
            'virus_id': -1,  
            'engine_id': -1  
        }

        try:
            scan_callback_fn = callback[0]
            self.disinfect_callback_fn = callback[1]
            self.update_callback_fn = callback[2]
            self.quarantine_callback_fn = callback[3]
        except IndexError:
            pass

        file_info = k2file.FileStruct(filename)
        file_scan_list = [file_info]

        is_sub_dir_scan = True

        while len(file_scan_list):
            try:
                t_file_info = file_scan_list.pop(0)  
                real_name = t_file_info.get_filename()

                if os.path.isdir(real_name):
                    real_name = os.path.abspath(real_name)

                    ret_value['result'] = False  
                    ret_value['filename'] = real_name  
                    ret_value['file_struct'] = t_file_info  
                    ret_value['scan_state'] = kernel.NOT_FOUND  

                    self.result['Folders'] += 1  

                    if self.options['opt_list']:  
                        self.call_scan_callback_fn(scan_callback_fn, ret_value)

                    if is_sub_dir_scan:
                        flist = glob.glob1(real_name, '*')
                        tmp_flist = []

                        for rfname in flist:
                            rfname = os.path.join(real_name, rfname)
                            tmp_info = k2file.FileStruct(rfname)
                            tmp_flist.append(tmp_info)

                        file_scan_list = tmp_flist + file_scan_list

                    if self.options['opt_nor']: 
                        is_sub_dir_scan = False  
                elif os.path.isfile(real_name) or t_file_info.is_archive():  
                    self.result['Files'] += 1 

                    if real_name == '':  
                        ret, ret_fi = self.unarc(t_file_info)
                        if ret:
                            t_file_info = ret_fi  
                        else:  
                            if ret_fi:  
                                ret_value['result'] = ret  
                                ret_value['engine_id'] = -1  
                                ret_value['virus_name'] = ret_fi  
                                ret_value['virus_id'] = -1  
                                ret_value['scan_state'] = kernel.ERROR 
                                ret_value['file_struct'] = t_file_info 

                                if self.options['opt_list']: 
                                    self.call_scan_callback_fn(scan_callback_fn, ret_value)

                                continue

                    if self.options['opt_debug']:  
                        ret_value['result'] = False  
                        ret_value['engine_id'] = -1  
                        ret_value['virus_name'] = 'debug' 
                        ret_value['virus_id'] = -1  
                        ret_value['scan_state'] = kernel.ERROR 
                        ret_value['file_struct'] = t_file_info  

                        self.call_scan_callback_fn(scan_callback_fn, ret_value)

                    ff = self.format(t_file_info)

                    ret, vname, mid, scan_state, eid = self.__scan_file(t_file_info, ff)
                    if self.options['opt_feature'] != 0xffffffff:  
                        self.__feature_file(t_file_info, ff, self.options['opt_feature'])

                    if ret: 
                        if scan_state == kernel.INFECTED:
                            self.result['Infected_files'] += 1
                        elif scan_state == kernel.SUSPECT:
                            self.result['Suspect_files'] += 1
                        elif scan_state == kernel.WARNING:
                            self.result['Warnings'] += 1

                        self.identified_virus.update([vname])

                    ret_value['result'] = ret  
                    ret_value['engine_id'] = eid  
                    ret_value['virus_name'] = vname  
                    ret_value['virus_id'] = mid  
                    ret_value['scan_state'] = scan_state 
                    ret_value['file_struct'] = t_file_info  

                    if move_master_file:
                        if t_master_file != t_file_info.get_master_filename():
                            self.__arcclose()
                            self.__quarantine_file(t_master_file)
                            move_master_file = False

                    if ret_value['result']:  
                        t_master_file = t_file_info.get_master_filename()

                        if not self.quarantine_name.get(t_master_file, None):
                            self.quarantine_name[t_master_file] = ret_value['virus_name']

                        action_type = self.call_scan_callback_fn(scan_callback_fn, ret_value)

                        if self.options['opt_move'] or self.options['opt_copy']:
                            if t_file_info.get_additional_filename() == '':
                                self.__arcclose()
                                self.__quarantine_file(t_master_file)
                                move_master_file = False
                            else:
                                move_master_file = True
                        else:  
                            if action_type == k2const.K2_ACTION_QUIT:  
                                return 0

                            d_ret = self.__disinfect_process(ret_value, action_type)

                            if d_ret:  
                                if self.options['opt_dis'] or \
                                   (action_type == k2const.K2_ACTION_DISINFECT or action_type == k2const.K2_ACTION_DELETE):
                                    if os.path.exists(t_file_info.get_filename()):
                                        t_file_info.set_modify(True)
                                        file_scan_list = [t_file_info] + file_scan_list
                                    else:
                                        self.__update_process(t_file_info)
                    else:
                        self.__update_process(t_file_info)

                        try:
                            arc_file_list = self.arclist(t_file_info, ff)
                            if len(arc_file_list):
                                file_scan_list = arc_file_list + file_scan_list

                        except zipfile.BadZipfile:
                            pass

                        if self.options['opt_list']:  
                            self.call_scan_callback_fn(scan_callback_fn, ret_value)
            except KeyboardInterrupt:
                return 1 
            except:
                if k2const.K2DEBUG:
                    import traceback
                    print traceback.format_exc()
                pass

        self.__update_process(None, True) 

        if move_master_file:
            self.__arcclose()
            self.__quarantine_file(t_master_file)
            move_master_file = False

        return 0  

    def call_scan_callback_fn(self, a_scan_callback_fn, ret_value):
        if isinstance(a_scan_callback_fn, types.FunctionType):
            fs = ret_value['file_struct']  
            rep_path = self.disable_path.sub('', fs.get_additional_filename())
            fs.set_additional_filename(rep_path)
            ret_value['file_struct'] = fs

            return a_scan_callback_fn(ret_value)

    def __quarantine_file(self, filename):
        if self.options['infp_path'] and (self.options['opt_move'] or self.options['opt_copy']):
            is_success = False

            try:
                if self.options['opt_qname']:
                    x = self.quarantine_name.get(filename, None)
                    if x:
                        q_path = os.path.join(self.options['infp_path'], x)
                        self.quarantine_name.pop(filename)
                    else:
                        q_path = self.options['infp_path']
                else:
                    q_path = self.options['infp_path']

                if not os.path.exists(q_path):
                    os.makedirs(q_path)  

                if self.options['opt_qhash']: 
                    t_filename = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
                else:
                    t_filename = os.path.split(filename)[-1]

                fname = os.path.join(q_path, t_filename)
                t_quarantine_fname = fname
                count = 1
                while True:
                    if os.path.exists(t_quarantine_fname):
                        t_quarantine_fname = '%s (%d)' % (fname, count)  
                        count += 1
                    else:
                        break

                if self.options['opt_move']:
                    shutil.move(filename, t_quarantine_fname) 
                elif self.options['opt_copy']:
                    shutil.copy(filename, t_quarantine_fname)  
                    q_type = k2const.K2_QUARANTINE_COPY

                is_success = True
            except (shutil.Error, OSError) as e:
                pass

            if isinstance(self.quarantine_callback_fn, types.FunctionType):
                if self.options['opt_copy']:
                    q_type = k2const.K2_QUARANTINE_COPY
                else:
                    q_type = k2const.K2_QUARANTINE_MOVE

                self.quarantine_callback_fn(filename, is_success, q_type)

    def __update_process(self, file_struct, immediately_flag=False):
        if immediately_flag is False:
            if len(self.update_info) == 0:  
                self.update_info.append(file_struct)
            else:
                n_file_info = file_struct  
                p_file_info = self.update_info[-1]  

                if p_file_info.get_master_filename() == n_file_info.get_master_filename() and \
                        n_file_info.get_archive_engine_name() is not None:
                    if p_file_info.get_level() <= n_file_info.get_level():
                        self.update_info.append(n_file_info)
                    else:
                        ret_file_info = p_file_info
                        while ret_file_info.get_level() != n_file_info.get_level():
                            ret_file_info = self.__update_arc_file_struct(ret_file_info)
                            self.update_info.append(ret_file_info)  
                        self.update_info.append(n_file_info)  
                else:
                    if len(self.update_info) == 1:  
                        self.__arcclose()
                        self.update_info = [file_struct]
                    else:
                        immediately_flag = True

        if immediately_flag:
            self.__arcclose()

            if len(self.update_info) > 1:  
                ret_file_info = None

                while len(self.update_info):
                    p_file_info = self.update_info[-1]  
                    ret_file_info = self.__update_arc_file_struct(p_file_info)

                    if len(self.update_info):  
                        self.update_info.append(ret_file_info)

                self.update_info = [file_struct]

    def __update_arc_file_struct(self, p_file_info):
        import kernel

        t = []

        arc_level = p_file_info.get_level()
        arc_engine = p_file_info.get_archive_engine_name()
        if arc_engine:
            arc_engine = arc_engine.split(':')[0]

        while len(self.update_info):
            ename = self.update_info[-1].get_archive_engine_name()
            if ename:
                ename = ename.split(':')[0]

            if self.update_info[-1].get_level() == arc_level and ename == arc_engine:
                t.append(self.update_info.pop())
            else:
                break

        t.reverse() 

        ret_file_info = self.update_info.pop()

        b_update = False

        for finfo in t:
            if finfo.is_modify():
                b_update = True
                break

        if b_update:  
            arc_name = t[0].get_archive_filename()
            arc_engine_id = t[0].get_archive_engine_name()
            can_arc = t[-1].get_can_archive()


            ret = False
            if can_arc == kernel.MASTER_PACK:  
                for inst in self.kavmain_inst:
                    try:
                        ret = inst.mkarc(arc_engine_id, arc_name, t)
                        if ret:  
                            break
                    except AttributeError:
                        continue
            elif can_arc == kernel.MASTER_DELETE:  
                os.remove(arc_name)
                ret = True

            if ret:
                ret_file_info.set_modify(True)  
                if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                    self.update_callback_fn(ret_file_info, True)
            else:
                ret_file_info.set_modify(False)  
                if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                    self.update_callback_fn(ret_file_info, False)

        for tmp in t:
            t_fname = tmp.get_filename()
            if os.path.exists(t_fname):
                try:
                    os.remove(t_fname)
                except OSError:
                    pass
        return ret_file_info

    def __arcclose(self):
        for i, inst in enumerate(self.kavmain_inst):
            try:
                inst.arcclose()
            except AttributeError:
                pass

    def __disinfect_process(self, ret_value, action_type):
        if action_type == k2const.K2_ACTION_IGNORE:  
            return

        t_file_info = ret_value['file_struct']  
        mid = ret_value['virus_id']
        eid = ret_value['engine_id']

        d_fname = t_file_info.get_filename()
        d_ret = False

        if action_type == k2const.K2_ACTION_DISINFECT:  
            d_ret = self.disinfect(d_fname, mid, eid)
            if d_ret:
                self.result['Disinfected_files'] += 1  
        elif action_type == k2const.K2_ACTION_DELETE: 
            try:
                os.remove(d_fname)
                d_ret = True
                self.result['Deleted_files'] += 1  
            except (IOError, OSError) as e:
                d_ret = False

        t_file_info.set_modify(d_ret)  

        if isinstance(self.disinfect_callback_fn, types.FunctionType):
            self.disinfect_callback_fn(ret_value, action_type)

        return d_ret

    def __scan_file(self, file_struct, fileformat):
        import kernel

        if self.verbose:
            print '[*] KavMain.__scan_file() :'

        fp = None
        mm = None

        try:
            ret = False
            vname = ''
            mid = -1
            scan_state = kernel.NOT_FOUND
            eid = -1

            filename = file_struct.get_filename() 
            filename_ex = file_struct.get_additional_filename() 

            if os.path.isfile(filename) is False:
                raise EngineKnownError('File is not found!')

            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret, vname, mid, scan_state = inst.scan(mm, filename, fileformat, filename_ex)
                    if ret: 
                        eid = i  

                        if self.verbose:
                            print '    [-] %s.__scan_file() : %s' % (inst.__module__, vname)

                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()

            if fp:
                fp.close()

            return ret, vname, mid, scan_state, eid
        except (EngineKnownError, ValueError) as e:
            pass
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            if k2const.K2DEBUG:
                import traceback
                print traceback.format_exc()
            self.result['IO_errors'] += 1 

        if mm:
            mm.close()

        if fp:
            fp.close()

        return False, '', -1, kernel.NOT_FOUND, -1

    def __feature_file(self, file_struct, fileformat, malware_id):
        if self.verbose:
            print '[*] KavMain.__feature_file() :'

        try:
            ret = False

            filename = file_struct.get_filename()  
            filename_ex = file_struct.get_additional_filename()  

            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret = inst.feature(mm, filename, fileformat, filename_ex, malware_id)
                    if ret:  
                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()
            if fp:
                fp.close()

            return ret
        except (IOError, EngineKnownError, OSError) as e:
            pass

        return False

    def disinfect(self, filename, malware_id, engine_id):
        ret = False

        if self.verbose:
            print '[*] KavMain.disinfect() :'

        try:
            inst = self.kavmain_inst[engine_id]
            ret = inst.disinfect(filename, malware_id)

            if self.verbose:
                print '    [-] %s.disinfect() : %s' % (inst.__module__, ret)
        except AttributeError:
            pass

        return ret

    def unarc(self, file_struct):
        import kernel

        rname_struct = None

        try:
            if file_struct.is_archive():  
                arc_engine_id = file_struct.get_archive_engine_name()  
                arc_name = file_struct.get_archive_filename()
                name_in_arc = file_struct.get_filename_in_archive()

                for inst in self.kavmain_inst:
                    try:
                        unpack_data = inst.unarc(arc_engine_id, arc_name, name_in_arc)

                        if unpack_data:
                            rname = self.temp_path.mktemp()
                            fp = open(rname, 'wb')
                            fp.write(unpack_data)
                            fp.close()

                            try:
                                can_arc = inst.getinfo()['make_arc_type']
                            except KeyError:
                                can_arc = kernel.MASTER_IGNORE
                            except AttributeError:
                                can_arc = kernel.MASTER_IGNORE

                            rname_struct = file_struct
                            rname_struct.set_filename(rname)
                            rname_struct.set_can_archive(can_arc)

                            if self.options['opt_sigtool']:
                                sig_fname = os.path.split(rname)[1]
                                shutil.copy(rname, sig_fname)

                                t = rname_struct.get_additional_filename()
                                if t[0] == '/' or t[0] == '\\':
                                    t = t[1:]
                                msg = '%s : %s\n' % (sig_fname, t)
                                fp = open('sigtool.log', 'at')
                                fp.write(msg)
                                fp.close()

                            break  
                    except (AttributeError, struct.error) as e:
                        continue
                    except RuntimeError:  
                        return False, 'password protected'
                    except MemoryError:
                        return False, None
                else:  # end for
                    rname = self.temp_path.mktemp()
                    fp = open(rname, 'wb')
                    fp.close()

                    rname_struct = file_struct
                    rname_struct.set_filename(rname)
                    rname_struct.set_can_archive(kernel.MASTER_IGNORE)
                return True, rname_struct
        except IOError:
            pass

        return False, None

    def arclist(self, file_struct, fileformat):
        import kernel

        file_scan_list = []  

        rname = file_struct.get_filename()
        deep_name = file_struct.get_additional_filename()
        mname = file_struct.get_master_filename()
        level = file_struct.get_level()

        for inst in self.kavmain_inst:
            is_archive_engine = False
            can_arc = kernel.MASTER_IGNORE

            try:
                ret_getinfo = inst.getinfo()
                if 'engine_type' in ret_getinfo:
                    if ret_getinfo['engine_type'] == kernel.ARCHIVE_ENGINE:  
                        is_archive_engine = True

                if 'make_arc_type' in ret_getinfo:
                    can_arc = ret_getinfo['make_arc_type']
            except AttributeError:
                pass

            try:
                arc_list = []  

                if self.options['opt_arc']:
                    arc_list = inst.arclist(rname, fileformat)

                    if len(arc_list) and is_archive_engine:
                        self.result['Packed'] += 1
                else:
                    if not is_archive_engine:
                        arc_list = inst.arclist(rname, fileformat)
            except AttributeError:
                pass

            if len(arc_list):  
                for alist in arc_list:
                    arc_id = alist[0]  
                    name = alist[1]  

                    if len(deep_name):  
                        try:
                            deep_name1 = deep_name
                            name1 = name

                            if type(deep_name) != type(name):
                                if isinstance(deep_name, unicode):
                                    name1 = name.decode('utf-8', 'ignore')
                                elif isinstance(name, unicode):
                                    deep_name1 = deep_name.decode('utf-8', 'ignore')

                            dname = '%s/%s' % (deep_name1, name1)
                        except UnicodeDecodeError:
                            continue
                    else:
                        dname = '%s' % name

                    fs = k2file.FileStruct()
                    fs.set_archive(arc_id, rname, name, dname, mname, False, can_arc, level+1)
                    file_scan_list.append(fs)


        return file_scan_list

    def format(self, file_struct):
        ret = {}
        filename = file_struct.get_filename()
        filename_ex = file_struct.get_additional_filename()  

        fp = None
        mm = None

        try:
            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for inst in self.kavmain_inst:
                try:
                    ff = inst.format(mm, filename, filename_ex)
                    if ff:
                        ret.update(ff)
                except AttributeError:
                    pass
        except (IOError, EngineKnownError, ValueError, OSError) as e:
            pass

        if mm:
            mm.close()

        if fp:
            fp.close()

        return ret

    def get_version(self):
        return self.max_datetime

    def set_options(self, options=None):
        if options:
            self.options['opt_arc'] = options.opt_arc
            self.options['opt_nor'] = options.opt_nor
            self.options['opt_list'] = options.opt_list
            self.options['opt_move'] = options.opt_move
            self.options['opt_copy'] = options.opt_copy
            self.options['opt_dis'] = options.opt_dis
            self.options['infp_path'] = options.infp_path
            self.options['opt_verbose'] = options.opt_verbose
            self.options['opt_sigtool'] = options.opt_sigtool
            self.options['opt_debug'] = options.opt_debug
            self.options['opt_feature'] = options.opt_feature
            self.options['opt_qname'] = options.opt_qname
            self.options['opt_qhash'] = options.opt_qhash
        else:  
            self.options['opt_arc'] = False
            self.options['opt_nor'] = False
            self.options['opt_list'] = False
            self.options['opt_move'] = False
            self.options['opt_copy'] = False
            self.options['opt_dis'] = False
            self.options['infp_path'] = None
            self.options['opt_verbose'] = False
            self.options['opt_sigtool'] = False
            self.options['opt_debug'] = False
            self.options['opt_feature'] = 0xffffffff
            self.options['opt_qname'] = False
            self.options['opt_qhash'] = False
        return True

    def set_result(self):
        self.result['Folders'] = 0 
        self.result['Files'] = 0  
        self.result['Packed'] = 0  
        self.result['Infected_files'] = 0  
        self.result['Suspect_files'] = 0  
        self.result['Warnings'] = 0  
        self.result['Identified_viruses'] = 0  
        self.result['Disinfected_files'] = 0 
        self.result['Deleted_files'] = 0  
        self.result['IO_errors'] = 0  

    def get_result(self):
        self.result['Identified_viruses'] = len(self.identified_virus)
        return self.result

    def get_signum(self):
        signum = 0  

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()

                if 'sig_num' in ret:
                    signum += ret['sig_num']
            except AttributeError:
                continue

        return signum