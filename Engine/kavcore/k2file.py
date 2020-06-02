# -*- coding:utf-8 -*-


import os
import re
import glob
import shutil
import tempfile
class K2Tempfile:
    def __init__(self):
        self.re_pid = re.compile(r'ktmp([0-9a-f]{5})$', re.IGNORECASE)

        self.temp_path = os.path.join(tempfile.gettempdir(), 'ktmp%05x' % os.getpid())

        if not os.path.exists(self.temp_path):
            try:
                os.mkdir(self.temp_path)
            except (IOError, OSError) as e:
                self.temp_path = tempfile.gettempdir()

    def gettempdir(self):
        return self.temp_path

    def mktemp(self):
        return tempfile.mktemp(prefix='ktmp', dir=self.temp_path)

    def removetempdir(self):
        try:
            if os.path.exists(self.temp_path):
                shutil.rmtree(self.temp_path)
        except OSError:
            pass

        '''
        fl = glob.glob(os.path.join(tempfile.gettempdir(), 'ktmp*'))
        if len(fl):
            for tname in fl:
                if os.path.isdir(tname):
                    tpath = self.re_pid.search(tname)
                    if tpath:  # 정상적으로 임시 폴더가 생겼음
                        if psutil.pid_exists(int(tpath.groups()[0], 16)) is False:
                            try:
                                shutil.rmtree(tname)
                            except OSError:
                                pass
                elif os.path.isfile(tname):
                    try:
                        os.remove(tname)
                    except OSError:
                        pass
        '''

class FileStruct:
    def __init__(self, filename=None, level=0):
        self.__fs = {}

        if filename:
            self.set_default(filename, level)

    def set_default(self, filename, level):
        import kernel

        self.__fs['is_arc'] = False  
        self.__fs['arc_engine_name'] = None  
        self.__fs['arc_filename'] = ''  
        self.__fs['filename_in_arc'] = ''  
        self.__fs['real_filename'] = filename  
        self.__fs['additional_filename'] = ''   
        self.__fs['master_filename'] = filename  
        self.__fs['is_modify'] = False  
        self.__fs['can_arc'] = kernel.MASTER_IGNORE 
        self.__fs['level'] = level  

    def is_archive(self):  
        return self.__fs['is_arc']

    def get_archive_engine_name(self):  
        return self.__fs['arc_engine_name']

    def get_archive_filename(self):  
        return self.__fs['arc_filename']

    def get_filename_in_archive(self):  
        return self.__fs['filename_in_arc']

    def get_filename(self):  
        return self.__fs['real_filename']

    def set_filename(self, fname):  
        self.__fs['real_filename'] = fname

    def get_master_filename(self):  
        return self.__fs['master_filename']  

    def get_additional_filename(self):
        return self.__fs['additional_filename']

    def set_additional_filename(self, filename):
        self.__fs['additional_filename'] = filename

    def is_modify(self):  
        return self.__fs['is_modify']

    def set_modify(self, modify): 
        self.__fs['is_modify'] = modify

    def get_can_archive(self):  
        return self.__fs['can_arc']

    def set_can_archive(self, mode):  
        self.__fs['can_arc'] = mode

    def get_level(self):  
        return self.__fs['level']

    def set_level(self, level):  
        self.__fs['level'] = level

    def set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc, level):
        self.__fs['is_arc'] = True  
        self.__fs['arc_engine_name'] = engine_id  
        self.__fs['arc_filename'] = rname  
        self.__fs['filename_in_arc'] = fname  
        self.__fs['real_filename'] = ''  
        self.__fs['additional_filename'] = dname  
        self.__fs['master_filename'] = mname 
        self.__fs['is_modify'] = modify  
        self.__fs['can_arc'] = can_arc  
        self.__fs['level'] = level  