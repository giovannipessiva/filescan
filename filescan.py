#!/usr/bin/env python

# FileScan, version 1.2.2
# Copyright (C) 2012, Giovanni Pessiva <giovanni.pessiva at gmail.com>
# All rights reserved.
#
# This software is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by  
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# It is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software. If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import shutil
import magic
import StringIO
import re
import hashlib
import subprocess
import shlex
import zipfile
import cStringIO

from time import time
from androguard.core import androconf
from androguard.core.bytecodes.apk import ARSCParser

INFECTED_DEX_RISK           = 0
INFECTED_ELF_RISK           = 1
HIDDEN_APK_RISK             = 2
HIDDEN_ELF_RISK             = 3
HIDDEN_TXT_RISK             = 4
EMBEDDED_APK                = 5
SHELL_RISK                  = 6
SHELL_INSTALL_RISK          = 7
SHELL_PRIVILEGE_RISK        = 8
SHELL_OTHER_RISK            = 9

LOW_RISK                    = "low"
HIGH_RISK                   = "high"

NULL_MALWARE_RISK           = "null"
AVERAGE_MALWARE_RISK        = "average"
HIGH_MALWARE_RISK           = "high"
UNACCEPTABLE_MALWARE_RISK   = "unacceptable"


class FileScan :
    """
        Analyze the files inside an archive, listing interesting files such as:
        - textual files
        - android binary xml
        - dex code
        - apk, zip, jar, gzip, tar
        - other compressed archives
        - compiled executable or resources
    """
        
    def __init__(self, file, raw=False, type="zip", apk_export_path="",
                    ENABLE_NET_CONNECTION = True,
                    DEBUG_IGNORE_CMD = False,
                    DEBUG_IGNORE_URL = False,
                    DEBUG_IGNORE_SMS = False) :
        """
            @param file : specify the path of the file, or raw data
            @param raw : specify (boolean) if "file" is a path or raw data
            @param type : specify the archive type: "zip", "gzip", "tar", "rar"
            @param apk_export_path: specify a path where to export the embedded apk files
                            found inside this package (e.g.: "/home/giova/samples/")
            @param ENABLE_NET_CONNECTION : flag for disabling the connection
                            to the online malware lookup service
            @param DEBUG_IGNORE_CMD : flag for disabling the search for shell commands
            @param DEBUG_IGNORE_URL : flag for disabling the search for URL addresses
            @param DEBUG_IGNORE_SMS :  flag for disabling the search for phone numbers
        """ 
        if file is None :
            raise Exception("Missing parameter: file.")
        if raw==False and not os.path.exists(file) :
            raise Exception("The apk file can not be found: " + file)

        # Parameters
        self.apk_export_path = apk_export_path # Path where to save embedded apk (if any will be found)
        self.enable_net_connection = ENABLE_NET_CONNECTION # Dont connect to Malware Hash Registry
        self.ignore_cmd = DEBUG_IGNORE_CMD # Dont search for shell commands
        self.ignore_url = DEBUG_IGNORE_URL # Dont search for URL addresses
        self.ignore_sms = DEBUG_IGNORE_SMS # Dont search for phone numbers
        
        # Dictionaries of <file name> : <data>
        self.files = {} # store raw data of interesting files
        self.files_types_descr = {} # store file type description
        self.files_types_mime = {} # store file mime type
        self.files_compressed_filescan = {} # store FileScan objects
        
        # Dictionary of <file type> : <count of total files>
        self.types = {}
        
        # Strings associated to file types
        self.TYPE_MULTIMEDIA = "multimedia"
        self.TYPE_BINARY_XML = "android xml"
        self.TYPE_PACKAGE = "android apk"
        self.TYPE_ARCHIVE = "compressed archive"
        self.TYPE_XML = "xml"
        self.TYPE_TEXT = "text"
        self.TYPE_DEX = "dex"
        self.TYPE_ELF = "elf"
        self.TYPE_ARSC = "android resource"
        self.TYPE_BINARY = "unknown binary"
        self.TYPE_OTHER = "other"
        self.TYPE_EMPTY = "empty file"
        
        # Lists of <file name>
        self.filelist_text = []
        self.filelist_xml = []
        self.filelist_dex = []
        self.filelist_elf = []
        self.filelist_apk = []
        self.filelist_zip = []
        self.filelist_gzip = []
        self.filelist_tar = []
        self.filelist_rar = []
        self.filelist_arsc = []
        self.filelist_multimedia = []
        self.filelist_other = []    #file type known but not managed
        self.filelist_unknown = [] #file type unknown
        
        # Lists of extensions used to detect changes
        self.common_extensions = ["png","jpg","jpeg","gif","bmp","wav","ogg","mp3","ttf","zip"]    # black list
        self.elf_extensions = ["so","exe"]    # white list
        self.apk_extensions = ["apk","jar"]    # white list
        
        # Compiled regular expressions
        self.re_script = {}
        #SHELL_RISK
        self.re_script[0] =  re.compile(r"^(#!/.*)", re.IGNORECASE)
        #SHELL_INSTALL_RISK
        self.re_script[1] =  re.compile(r"^(.*[^a-z0-9\n])?cp +.+ system/app/.*", re.IGNORECASE | re.MULTILINE)
        self.re_script[2] =  re.compile(r"^(.*[^a-z0-9\n])?pm +install[^a-z0-9\n].*", re.IGNORECASE | re.MULTILINE)
        self.re_script[3] =  re.compile(r"^(.*[^a-z0-9\n])?am +start[^a-z0-9\n].*", re.IGNORECASE | re.MULTILINE)
        #SHELL_PRIVILEGE_RISK
        self.re_script[4] =  re.compile(r"^(.*[^a-z0-9\n])?(chown|chmod) +.*", re.IGNORECASE | re.MULTILINE)
        self.re_script[5] =  re.compile(r"^(.*[^a-z0-9\n])?mount +.* *remount+.*", re.IGNORECASE | re.MULTILINE)
        self.re_script[6] =  re.compile(r"^(.*[^a-z0-9\n])?(sudo|su +-c|system/bin/su) +.*", re.IGNORECASE | re.MULTILINE)
        #SHELL_OTHER_RISK
        self.re_script[7] = re.compile(r"(^.*[^a-z0-9\n])?setprop +.*", re.IGNORECASE | re.MULTILINE)
        self.re_script[8] = re.compile(r"^(.*[^a-z0-9\n])?insmod .*", re.IGNORECASE | re.MULTILINE)
        self.re_script[9] = re.compile(r"^.*system/bin/.*", re.IGNORECASE | re.MULTILINE)
        self.re_script[10] = re.compile(r"^.* +resolv.conf.*", re.IGNORECASE | re.MULTILINE)
        # Phone numbers
        self.re_sms1 = re.compile(r"(tel:(//)?)?\+?[0-9]{4,}")        
        
        accepted_chars = r"[a-z0-9\.\-_~:\?#\[\]@!\$&\(\)\*\+=]|(?:%[0-9a-f]{2})" #/ ;'"
        protocol = r'(?:https?|ftp|market):'
        authentication = r'(?:('+accepted_chars+r')+(?::('+accepted_chars+r')*)?@)?'
        
        # IP address dotted notation octets
        # excludes loopback network 0.0.0.0, reserved space >= 224.0.0.0, network & broacast addresses (first & last IP address of each class)
        regex1 = r'(?P<domain>(('+protocol+r'//)?'+authentication
        regex1 += r'(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}'
        regex1 += r'(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])))|'
        # URL
        regex1 += r'((?:'+protocol+r'//|www\.)'+authentication+r'(?!\d+(?:\.\d+)+)('+accepted_chars+r')+'
        # TLD identifier (http://data.iana.org/TLD/tlds-alpha-by-domain.txt)
        regex1 += r'\.(?:([a-z]{2,6})|(xn--[a-z0-9]{4,18}))))'
        # port number
        regex1 += r'(?::\d{2,5})?'
        # resource path
        regex1 += r'(?:/('+accepted_chars+')+)?'
        
        accepted_chars += r"|{[a-z0-9\.\-_~:\?#\[\]@!\$&\\\(\)\*\+=]+}|(?:%[0-9]+\$[a-z0-9,\+\-(#]+)"
        
        # IP address dotted notation octets
        # excludes loopback network 0.0.0.0, reserved space >= 224.0.0.0, network & broacast addresses (first & last IP address of each class)
        regex2 = r'(?P<domain>('+protocol+r'\\?/\\?/?'+authentication
        regex2 += r'(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\\?\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}'
        regex2 += r'(?:\\?\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])))|'
        # URL
        regex2 += r'((?:'+protocol+r'[\\]?/[\\]?/|www\\?\.)'+authentication+r'(?!\d+(?:\.\d+)+)('+accepted_chars+r'|[\\])+'
        # TLD identifier (http://data.iana.org/TLD/tlds-alpha-by-domain.txt)
        regex2 += r'\.(?:([a-z]{2,6})|(xn--[a-z0-9]{4,18}))))'
        # port number
        regex2 += r'(?::\d{2,5})?'
        # resource path
        regex2 += r'(?:/('+accepted_chars+'|[\\])*('+accepted_chars+')+)?'

        # Regular URLs
        self.re_url1 = re.compile(regex1, re.IGNORECASE)
        #self.re_url1 = re.compile(r"((?:(https?|market|tel)://)|(?:www\.))(?:[a-z0-9-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=]|(?:%[0-9a-f]{2}))+", re.IGNORECASE)
        # Parametrical URLs
        self.re_url2 = re.compile(regex2, re.IGNORECASE)
        #self.re_url2 = re.compile(r"((?:(https?|market|tel):\\?/\\?/)|(?:www\.))(?:[a-z0-9-\._~:/\?#\[\]@!\$&'\(\)\*\+,;\\=]|(?:%[0-9a-f]{2})|{[a-z0-9-\._~:/\?#@!\$&'\+,;=]+})+", re.IGNORECASE)
        # URLs to ignore
        self.re_url_known = re.compile("(?:(?:(developer|schemas)\.android\.com)|(wc?3\.org)|(apple\.com/DTD)|(apache\.org)|(jquery\.com)|(developers\.facebook\.com))", re.IGNORECASE)
                        
        # Hashcodes of known infected binaries
        self.known_infected_elf = {}
        self.known_infected_elf["c4269275058f4f5239b45db88257df38c7d6cca2"] = "asroot-asroot-1"
        self.known_infected_elf["a40181f2d912527af7371c490fbd36e48beb0d3f"] = "asroot-asroot-2"
        self.known_infected_elf["63cbf4dff428a6743191a63d70b4d83970d4ee43"] = "basebridge-rageagainstthecage"
        self.known_infected_elf["8d673db24815b1924c4fbff8f204c30e7570d4c2"] = "droiddream-exploid"
        self.known_infected_elf["bc41b82ae83661906d7445b5cf451f21f278846a"] = "droiddream-rageagainstthecage"
        self.known_infected_elf["38167159a4dd066ff525589183f8e68304fff2a6"] = "droidkungfu-kungfu"
        self.known_infected_elf["c6908dc5f7c072d89d0f8359a0a2add9658b016a"] = "droidkungfulotoor"
        self.known_infected_elf["611818ea2da9d302d6bcd9b61846d7fa9a65e96d"] = "gingermaster-gbfm.png"
        self.known_infected_elf["f7db5b53aab5730351d23ccedaafa0bc776f08b6"] = "gingermaster-runme.png"
        self.known_infected_elf["b703df668e41a8cf5bad44edf1ac65c915e5fe41"] = "zHash-lootor-extend"
        self.known_infected_elf["28feffc93c1ec4e0cfd382b047a85c47dafec740"] = "zHash-lootor-zhash"
        
        # Lists of data found during analysis, and their source files
        self.urls = []
        self.urls_domains = []
        self.urls_files = []
        self.urls2 = []
        self.urls2_domains = []
        self.urls2_files = []
        self.numbers = []
        self.numbers_files = []
        self.scripts = []
        self.scripts_files = []
        
        # Time required by the analysis method
        self.analysis_time = 0
        
        # Risk values and script counts, saved during the analysis for later use
        self.risks = {}
        self.script_count = {
            SHELL_RISK : 0,
            SHELL_INSTALL_RISK : 0,
            SHELL_PRIVILEGE_RISK : 0,
            SHELL_OTHER_RISK : 0
        }
        
        file_data = ""
        if raw==False :
            self.path=file
            file_data = open(file, 'rb').read()
        else :
            self.path=""
            file_data = file
        
        md5 = hashlib.md5()        
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(file_data)
        sha1.update(file_data)        
        sha256.update(file_data)
        self.checksum_md5 = md5.hexdigest()
        self.checksum_sha1 = sha1.hexdigest()  
        self.checksum_sha256 = sha256.hexdigest()  
        
        try : 
            # Use a custom magic file
            magic_descr = magic.Magic(magic_file="magic.mgc",mime=False)
            magic_mime = magic.Magic(magic_file="magic.mgc",mime=True)
        except Exception, e:
            # If it is not available, use the default magic file of the system
            magic_descr = magic.Magic(mime=False)
            magic_mime = magic.Magic(mime=True)
        
        if type=="zip" :
            # APK/Zip/Jar archive
            try :
                if not raw :
                    zip = zipfile.ZipFile( file, mode="r" )
                else :
                    fileobj = StringIO.StringIO(file)
                    zip = zipfile.ZipFile( fileobj, mode="r" )
            except Exception, e :
                # Typical errors:
                # "unpack requires a string argument of length 4" see http://bugs.python.org/issue14315
                # "File is not a zip file"
                if not raw :
                    print "problem while opening file:" + file
                raise e
            for f in zip.namelist() :
                try :
                    uncompressed_file = zip.read(f)
                    descr = magic_descr.from_buffer(uncompressed_file)
                    mime = magic_mime.from_buffer(uncompressed_file)
                    self._classify_file(mime, descr, uncompressed_file, f)
                except Exception, e :
                    # Invalid file, skip it
                    pass
        elif type=="gzip" :
            # GZip archive
            try:
                gzip = __import__("gzip")
            except ImportError:
                raise Exception("Module gzip not found")
            if not raw :
                f = gzip.GzipFile(filename=file, mode='rb')
            else :
                f = gzip.GzipFile(mode='rb', fileobj=StringIO.StringIO(file) ) 
            uncompressed_file = f.read()
            f.close()
            # Gzip archives contains a single file
            descr = magic_descr.from_buffer(uncompressed_file)
            mime = magic_mime.from_buffer(uncompressed_file)
            self._classify_file(mime, descr, uncompressed_file, "(unknown)")
        elif type=="tar" :
            # Tar archive
            try:
                tarfile = __import__("tarfile")
            except ImportError:
                raise Exception("Module tarfile not found")
            if not raw :
                tar = tarfile.open(filename=file, mode='r')
            else :
                tar = tarfile.open(mode='r', fileobj=StringIO.StringIO(file) )
            for f in tar.getnames() :
                uncompressed_file = tar.extractfile(f).read()
                descr = magic_descr.from_buffer(uncompressed_file)
                mime = magic_mime.from_buffer(uncompressed_file)
                self._classify_file(mime, descr, uncompressed_file, f)
            tar.close()
        elif type=="rar" :
            # Rar archive
            try:
                rarfile = __import__("rarfile")
            except ImportError:
                raise Exception("Need to install module rarfile: http://rarfile.berlios.de/")
            if not raw :
                rar = rarfile.RarFile(file)
            else :
                tmp = open("tmp_filescan_rarfile.rar",'w')
                tmp.write(file)
                tmp.close()
                rar = rarfile.RarFile( "tmp_filescan_rarfile.rar")
            for f in rar.namelist() :
                try :
                    uncompressed_file = rar.read(f)
                    descr = magic_descr.from_buffer(uncompressed_file)
                    mime = magic_mime.from_buffer(uncompressed_file)
                    self._classify_file(mime, descr, uncompressed_file, f.replace("\\","/"))
                except Exception, e :
                    # Invalid file, skip it
                    pass
            if raw :
              os.remove("tmp_filescan_rarfile.rar")  
        else :
            raise Exception("Unexpected archive type; supported values are \"zip\", \"gzip\", \"tar\" \"rar\"");
    
    def _classify_file(self, file_mime, file_descr, file_raw, file_name="") :
        """
            Analyze a file, checking its type
            If it has an interesting format (eg. txt, dex, zip) memorize it.
            If it has an unsupported format (eg. TTComp, LUA), memorize it without the raw data
            If it has an uninteresting format (eg. PNG, ogg), skip it
            
            @param file_mime : file mime type
            @param file_descr : file type description
            @param file_raw : file raw data
            @param file_name : name of the file (if available)
        """
        if not file_name=="" :
            extension = os.path.splitext(file_name)[1][1:].lower()
        else :
            file_name = "(unknown)"
            extension = "(unknown)"
        self.files_types_descr[file_name] = file_descr
        self.files_types_mime[file_name] = file_mime
        mime_type = file_mime.partition("/")[0]
        mime_subtype = file_mime.partition("/")[2].partition(";")[0]
        if mime_type == "image" :
            self.filelist_multimedia.append(file_name)
            self._increment_type_count(self.TYPE_MULTIMEDIA)
        elif mime_type == "application" :
            if mime_subtype == "octet-stream" :
                if "DBase" in file_descr and androconf.is_android_raw(file_raw) == "AXML" :
                    # Android's binary XML
                    self.filelist_other.append(file_name)
                    self._increment_type_count(self.TYPE_BINARY_XML)   
                elif file_descr.startswith("Dalvik dex") :
                    # Dalvik dex file
                    self.filelist_dex.append(file_name)
                    self.files[file_name] = file_raw
                    self._increment_type_count(self.TYPE_DEX) 
                elif file_descr == "data" :
                    if extension == "arsc" :
                        # Compiled resources
                        self.filelist_arsc.append(file_name)
                        # Decompile and save the strings values
                        arscp = ARSCParser(file_raw)
                        self.files[file_name] = arscp.get_strings_resources()
                        self._increment_type_count(self.TYPE_ARSC)              
                    else :
                        # Unknown binary format
                        self.filelist_unknown.append(file_name)
                        self._increment_type_count(self.TYPE_BINARY) 
                elif file_descr.startswith("Lua bytecode") :
                    # Lua bytecode
                    self.filelist_other.append(file_name)
                    self._increment_type_count(self.TYPE_OTHER)
                elif file_descr.startswith("compiled Java") :
                    # compiled Java class data
                    self.filelist_other.append(file_name)
                    self._increment_type_count(self.TYPE_OTHER)
                elif file_descr.startswith("Audio file") :
                    # Audio file with ID3 version
                    self.filelist_multimedia.append(file_name)
                    self._increment_type_count(self.TYPE_MULTIMEDIA)  
                elif file_descr.startswith("AppleDouble") :
                    # AppleDouble encoded Macintosh file
                    self.filelist_other.append(file_name)
                    self._increment_type_count(self.TYPE_OTHER)    
                elif file_descr.startswith("TTComp archive data") :
                    # TTComp archive data
                    self.filelist_other.append(file_name)
                    self._increment_type_count(self.TYPE_ARCHIVE)
                else :
                    # Unknown binary format
                    self.filelist_unknown.append(file_name)
                    self._increment_type_count(self.TYPE_BINARY)                
            elif mime_subtype == "ogg" :
                # should be harmless
                self.filelist_multimedia.append(file_name)
                self._increment_type_count(self.TYPE_MULTIMEDIA)
            elif mime_subtype == "xml" :
                self.filelist_xml.append(file_name)
                self.files[file_name] = file_raw
                self._increment_type_count(self.TYPE_XML)
            elif mime_subtype == "zip" :           
                if androconf.is_android_raw(file_raw) == "APK" and androconf.is_valid_android_raw(file_raw) :
                    self.filelist_apk.append(file_name)
                    self.files[file_name] = file_raw
                    self._increment_type_count(self.TYPE_PACKAGE)
                    if self.apk_export_path != "" :
                        # save this embedded apk to the filesystem, in the specified directory
                        sha1 = hashlib.sha1()
                        sha1.update(file_raw)        
                        checksum_sha1 = sha1.hexdigest()
                        try :
                            tmp = open(self.apk_export_path + checksum_sha1 + ".apk",'w')
                            tmp.write(file_raw)
                            tmp.close() 
                        except Exception, e :
                            print "Exception while exporting embedded apk "+file_name+":", e
                    self._scan_archive(file_name,"zip")
                else :
                    self.filelist_zip.append(file_name)
                    self.files[file_name] = file_raw
                    self._increment_type_count(self.TYPE_ARCHIVE)
                    self._scan_archive(file_name,"zip")
            elif mime_subtype == "x-gzip" :
                self.filelist_gzip.append(file_name)
                self.files[file_name] = file_raw
                self._increment_type_count(self.TYPE_ARCHIVE)
                self._scan_archive(file_name,"gzip")
            elif mime_subtype == "x-tar" :
                self.filelist_tar.append(file_name)
                self.files[file_name] = file_raw
                self._increment_type_count(self.TYPE_ARCHIVE)
                self._scan_archive(file_name,"tar")
            elif mime_subtype == "x-rar" or mime_subtype == "x-rar-compressed" :
                self.filelist_rar.append(file_name)
                self.files[file_name] = file_raw
                self._increment_type_count(self.TYPE_ARCHIVE)
                self._scan_archive(file_name,"rar")     
            elif (mime_subtype == "x-gtar" \
            or mime_subtype == "x-arc" \
            or mime_subtype == "x-archive"):
                self.filelist_other.append(file_name)
                self._increment_type_count(self.TYPE_ARCHIVE)
            elif mime_subtype == "x-sharedlib" :
                # ELF 32-bit LSB shared object
                self.filelist_elf.append(file_name)
                self.files[file_name] = file_raw
                self._increment_type_count(self.TYPE_ELF)  
            elif mime_subtype == "x-executable" :
                # ELF 32-bit LSB executable
                self.filelist_elf.append(file_name)
                self.files[file_name] = file_raw
                self._increment_type_count(self.TYPE_ELF)  
            elif mime_subtype == "x-font-ttf" :
                # TrueType font data
                self.filelist_other.append(file_name)
                self._increment_type_count(self.TYPE_OTHER) 
            elif mime_subtype == "x-empty" :
                self.filelist_other.append(file_name)
                self._increment_type_count(self.TYPE_EMPTY)  
            else :
                # unknown
                self.filelist_unknown.append(file_name)
                self._increment_type_count(self.TYPE_OTHER) 
        elif mime_type == "text":
            # third most frequent mime_type
            self.filelist_text.append(file_name)
            self.files[file_name] = file_raw
            self._increment_type_count(self.TYPE_TEXT)
        elif mime_type == "audio" or mime_type == "video":
            self.filelist_multimedia.append(file_name)
            self._increment_type_count(self.TYPE_MULTIMEDIA)

    def _increment_type_count(self, category) :
        tot = 0
        if category in self.types :
            tot = self.types[category]
        self.types[category] = tot + 1
              
    def _scan_archive(self, file, type) :
        """
            Recursively scan a compressed archive, by instantiating a new FileScan object
            @param file : specify the name of the file
            @param type : specify the archive format (zip, gzip, tar, rar)
        """ 
        raw_file = self.files[file]
        try :
            file_scan = FileScan(file = raw_file, raw = True, type = type,
                                apk_export_path = self.apk_export_path,
                                ENABLE_NET_CONNECTION = self.enable_net_connection,
                                DEBUG_IGNORE_CMD = self.ignore_cmd,
                                DEBUG_IGNORE_URL = self.ignore_url,
                                DEBUG_IGNORE_SMS = self.ignore_sms)
            self.files_compressed_filescan[file] = file_scan
        except Exception :
            # Invalid archive file, ignore it
            pass
        
    def get_sha1(self) :
        return self.checksum_sha1
        
    def get_analysis_time(self) : 
        return self.analysis_time

    def analyze_files(self, relative_path="") :
        """
            Return a value expressing the risk assigned to these files
            @param relative_path : needed only by internal recursion
        """
        self.analysis_time = 0
        start = time()
        risks = {
            INFECTED_DEX_RISK    : 0,
            INFECTED_ELF_RISK    : 0,
            HIDDEN_APK_RISK      : 0,
            HIDDEN_ELF_RISK      : 0,
            HIDDEN_TXT_RISK      : 0,
            EMBEDDED_APK         : 0,
            SHELL_RISK           : 0,
            SHELL_INSTALL_RISK   : 0,
            SHELL_PRIVILEGE_RISK : 0,
            SHELL_OTHER_RISK     : 0
        }
        # Initialize the count of the shell script files
        self.script_count[SHELL_RISK] = 0
        self.script_count[SHELL_INSTALL_RISK] = 0
        self.script_count[SHELL_PRIVILEGE_RISK] = 0
        self.script_count[SHELL_OTHER_RISK] = 0
        # Analyze every text file
        for f in self.filelist_text :
            self._analyze_file_readable(f)
        for f in self.filelist_xml :
            self._analyze_file_xml(f)
        for f in self.filelist_arsc :
            self._analyze_file_xml(f)  
        # Save the count of the shell script files
        risks[SHELL_RISK] += self.script_count[SHELL_RISK]
        risks[SHELL_INSTALL_RISK] += self.script_count[SHELL_INSTALL_RISK]
        risks[SHELL_PRIVILEGE_RISK] += self.script_count[SHELL_PRIVILEGE_RISK]
        risks[SHELL_OTHER_RISK] += self.script_count[SHELL_OTHER_RISK]
        # Count the textual files whose extension is in a black list
        # Count the elf binaries not in "lib/armeabi*" whose extension is not in a white list 
        # Count the apk files whose extension is not in a white list
        suspect_files = self._suspect_files()
        risks[HIDDEN_TXT_RISK]=len(suspect_files["txt"])
        risks[HIDDEN_ELF_RISK]=len(suspect_files["elf"])
        risks[HIDDEN_APK_RISK]=len(suspect_files["apk"])
        # Count the embedded apk files
        risks[EMBEDDED_APK] = len(self.filelist_apk)
        # Look for known infected ELF
        elf_infected=self.get_elf_infected(self._elf_checksum())
        # Check the detection rate for ELF and DEX                
        for file,result in self.get_detection_rate(self._elf_checksum()).iteritems() :
            if file in elf_infected :
                result = 100
            if result > 0 :
                risks[INFECTED_ELF_RISK] += int(result)
        for file,result in self.get_detection_rate(self._dex_checksum()).iteritems() :
            risks[INFECTED_DEX_RISK] += int(result)
            
        # Recursion on internal archives
        for k, v in self.files_compressed_filescan.iteritems() :
            relative_path=relative_path+k+"/"
            internal_risks = v.analyze_files(relative_path)
            risks[INFECTED_DEX_RISK]    += internal_risks[INFECTED_DEX_RISK]
            risks[INFECTED_ELF_RISK]    += internal_risks[INFECTED_ELF_RISK]
            risks[HIDDEN_APK_RISK]      += internal_risks[HIDDEN_APK_RISK]
            risks[HIDDEN_ELF_RISK]      += internal_risks[HIDDEN_ELF_RISK]
            risks[HIDDEN_TXT_RISK]      += internal_risks[HIDDEN_TXT_RISK]
            risks[EMBEDDED_APK]         += internal_risks[EMBEDDED_APK]
            risks[SHELL_RISK]           += internal_risks[SHELL_RISK]
            risks[SHELL_INSTALL_RISK]   += internal_risks[SHELL_INSTALL_RISK]
            risks[SHELL_PRIVILEGE_RISK] += internal_risks[SHELL_PRIVILEGE_RISK]
            risks[SHELL_OTHER_RISK]     += internal_risks[SHELL_OTHER_RISK]
  
        self.analysis_time = time() - start
        self.risks = risks
        return risks
    
    def get_risk_score(self) :
        """
        Return the risk score computed with risks values collected by analyze_files()
        """
        return int(RiskIndicator().get_risk(self.risks))
            
    def _analyze_file_readable(self, file, raw=False) :
        data = file
        if raw == False :
            data = self.files[file]
        else :
            file = "(unknown)"
        if not self.ignore_cmd == True :
            self._search_script(data, file)
        if not self.ignore_url == True :
            self._search_url(data, file)
        if not self.ignore_sms == True :
            self._search_sms(data, file)      
         
    def _analyze_file_xml(self, file, raw=False) :
        data = file
        if raw == False :
            data = self.files[file]
        if not self.ignore_url == True :
            self._search_url(data, file)
        if not self.ignore_sms == True :
            self._search_sms(data, file)      
 
    def get_apk(self) :
        list_apk = list(self.filelist_apk)  
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :  
            for internal in archive.get_apk() :
                list_apk.append(str(name+"/"+internal))
        return list_apk 
       
    def get_types_count(self) :
        """
            Return a dictionary with the count (by type) of the files found in the archive
        """
        types = dict(self.types)
        # Recursion on internal archives
        for archive, archive_fileScan in self.files_compressed_filescan.iteritems() :
            archive_types = archive_fileScan.get_types_count()
            for type, count in archive_types.iteritems() :
                if type in types :
                    types[type] = types[type] + archive_types[type] 
                else :
                    types[type] = archive_types[type]
        return types
            
    def get_files_list(self) :
        """
            Return a list of the files
        """
        files = []
        files += self.filelist_text
        files += self.filelist_xml
        files += self.filelist_dex
        files += self.filelist_elf
        files += self.filelist_multimedia
        files += self.filelist_other
        files += self.filelist_unknown
        # Recursion on internal archives
        for zip in self.filelist_zip :
            files.append(zip) 
            internal_list = self.files_compressed_filescan[zip].get_files_list()
            for f in internal_list :
                files.append(zip + "/" + f)
        for apk in self.filelist_apk :
            files.append(apk) 
            internal_list = self.files_compressed_filescan[apk].get_files_list()
            for f in internal_list :
                files.append(apk + "/" + f)
        for gzip in self.filelist_gzip :
            files.append(gzip) 
            internal_list = self.files_compressed_filescan[gzip].get_files_list()
            for f in internal_list :
                files.append(gzip + "/" + f)
        for tar in self.filelist_tar :
            files.append(tar) 
            internal_list = self.files_compressed_filescan[tar].get_files_list()
            for f in internal_list :
                files.append(tar + "/" + f)
        for rar in self.filelist_rar :
            files.append(rar) 
            internal_list = self.files_compressed_filescan[rar].get_files_list()
            for f in internal_list :
                files.append(rar + "/" + f)
        return files
        
    def get_suspect_files(self) :
        """
            Return a dictionary of all the interesting files (textual, compressed, compiled)
            which have unusual extensions (not matching with their magic number)
        """
        suspect_files = self._suspect_files()
        # Recursion on internal archives
        for k, v in self.files_compressed_filescan.iteritems() : 
            suspect = v.get_suspect_files()
            for txt,descr in suspect["txt"].iteritems() :
                suspect_files["txt"][k + "/" + txt] = descr
            for txt,descr in suspect["elf"].iteritems() :
                suspect_files["elf"][k + "/" + txt] = descr
            for txt,descr in suspect["apk"].iteritems() :
                suspect_files["apk"][k + "/" + txt] = descr
        return suspect_files
        
    def _suspect_files(self) :
        """
            Return a dictionary of interesting files (textual, compressed, compiled)
            which have unusual extensions (not matching with their magic number)
        """  
        suspect_files = {
            "txt" : {},
            "apk" : {},
            "elf" : {}
        }      
        for f in self.filelist_text :
            ext = os.path.splitext(f)[1][1:].lower()
            if (ext in self.common_extensions) :
                suspect_files["txt"][f] = self.files_types_descr[f]
        for f in self.filelist_elf :
            ext = os.path.splitext(f)[1][1:].lower()
            if (ext not in self.elf_extensions) :
                if "lib/armeabi" not in f :
                    suspect_files["elf"][f] = self.files_types_descr[f]
        for f in self.filelist_apk :
            ext = os.path.splitext(f)[1][1:].lower()
            if (ext not in self.apk_extensions) :
                suspect_files["apk"][f] = self.files_types_descr[f]
        return suspect_files
    
    def get_dex_checksum(self,type="md5") :
        """
            Return a dictionary that associate every dex file (recursively) to its checksum
            @param type : hash functions used (md5, sha1, sha224, sha256, sha384, sha512)
        """
        checksum = self._dex_checksum(type)
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :  
            result = archive.get_dex_checksum(type)
            for dex, hash in result.iteritems() :
                checksum[name+"/"+dex] = hash
        return checksum
        
    def _dex_checksum(self,type="md5") :
        """
            Return a dictionary that associate every dex file to its checksum
            @param type : hash functions used (md5, sha1, sha224, sha256, sha384, sha512)
        """
        checksum = {}
        if type == "md5" :
            hashobj = hashlib.md5()
        elif type == "sha1" :
            hashobj = hashlib.sha1()
        elif type == "sha224" :
            hashobj = hashlib.sha224()
        elif type == "sha256" :
            hashobj = hashlib.sha256()
        elif type == "sha384" :
            hashobj = hashlib.sha384()
        elif type == "sha512" :
            hashobj = hashlib.sha512()
        else :
            raise Exception("Unexpected value for parameter type in get_dex_checksum")
        for f in self.filelist_dex :
            m = hashobj.copy()
            m.update(self.files[f])
            checksum[f] = m.hexdigest()
        return checksum
    
    def get_elf_checksum(self,type="sha1") :
        """
            Return a dictionary that associate every ELF file (recursively) to its checksum
            @param type : hash functions used (md5, sha1, sha224, sha256, sha384, sha512)
        """
        checksum = self._elf_checksum(type)
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :  
            result = archive.get_elf_checksum(type)
            for elf, hash in result.iteritems() :
                checksum[name+"/"+elf] = hash
        return checksum
        
    def _elf_checksum(self,type="sha1") :
        """
            Return a dictionary that associate every ELF file to its checksum
            @param type : hash functions used (md5, sha1, sha224, sha256, sha384, sha512)
        """
        checksum = {}
        if type == "md5" :
            hashobj = hashlib.md5()
        elif type == "sha1" :
            hashobj = hashlib.sha1()
        elif type == "sha224" :
            hashobj = hashlib.sha224()
        elif type == "sha256" :
            hashobj = hashlib.sha256()
        elif type == "sha384" :
            hashobj = hashlib.sha384()
        elif type == "sha512" :
            hashobj = hashlib.sha512()
        else :
            raise Exception("Unexpected value for parameter type in get_elf_checksum")
        for f in self.filelist_elf :
            m = hashobj.copy()
            m.update(self.files[f])
            checksum[f] = m.hexdigest()
        return checksum
        
    def _query_mhr(self, hash) :
        """
            Handle a query to the Malware Hash Registry 
            http://www.team-cymru.org/Services/MHR/
            @param hash : hashcode to check
        """
        if self.enable_net_connection != True :
            result = 0
        else :
            try :
                FNULL = open('/dev/null', 'w')
                p = subprocess.Popen("whois -h hash.cymru.com " + hash, \
                                    stdout=subprocess.PIPE, \
                                    stderr=FNULL, \
                                    shell=True)
                response = p.communicate()[0]
                FNULL.close()
                result = int(shlex.split(response)[2])
            except :
                result = 0
        return result
    
    def _is_mhr_reachable(self) :
        """
            Test whether the whois service of hash.cymru.com is reachable
        """
        result = self._query_mhr("cbed16069043a0bf3c92fff9a99cccdc")
        if result == 0 :
            return False
        else :
            return True
            
    def get_detection_rate(self, files) :
        """
            Return the detection rate for the files hashes
            @param files : dictionary that associate file names to their hashcode
        """
        detection_rate = {}
        for file, hash in files.iteritems() :
            detection_rate[file] = self._query_mhr(hash)
        return detection_rate
    
    def get_elf_infected(self, files) :
        """
            Check if the ELF files are known malware
            @param files : dictionary that associate file names to their hashcode
        """
        elf_infected = {}
        for file, hash in files.iteritems() :
            if(hash in self.known_infected_elf) :
                elf_infected[file] = self.known_infected_elf[hash]
        return elf_infected    
    
    def get_scripts(self) :
        """
            Return a list of lines identified as script commands,
            found while performing method analyze_files(), and their source file
        """
        scripts = self.scripts
        scripts_files = self.scripts_files 
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :
            s, sf = archive.get_scripts() 
            scripts.extend(s)
            for file in sf :
                scripts_files.append(name+"/"+file)
        return (scripts, scripts_files)    
        
    def get_urls(self) :
        """
            Return the URLs found while performing method analyze_files()
            Return 3 lists of: complete URL, URL domain, and its source file
        """
        urls = self.urls
        domains = self.urls_domains
        files = self.urls_files
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :
            u, d, f = archive.get_urls()
            urls.extend(u)
            domains.extend(d)
            for file in f :
                files.append(name+"/"+file)
        return (urls, domains, files)
            
    def get_urls_encoded(self) :
        """
            Return a set of encoded URLs (with escape \ or parameters between {}),
            found while performing method analyze_files()
            Return 3 lists of: complete URL, URL domain, and its source file
        """
        urls = self.urls2
        domains = self.urls2_domains
        files = self.urls2_files
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :
            u, d, f = archive.get_urls_encoded()
            urls.extend(u)
            domains.extend(d)
            for file in f :
                files.append(name+"/"+file)
        return (urls, domains, files)
                    
    def get_numbers(self) :
        """
            Return a set of phone numbers found while performing
            the method analyze_files(), and their source file
        """
        numbers = self.numbers
        files = self.numbers_files
        # Recursion on internal archives
        for name, archive in self.files_compressed_filescan.iteritems() :
            n, f = archive.get_numbers()
            numbers.extend(n)
            for file in f :
                files.append(name+"/"+file)
        return (numbers, files)
        
    def _search_script(self, data, file) :
        """
            Apply regular expressions looking for shell commands
            @param data : text buffer
            @param file : name of the file
        """
        max_line_length = len(max(data.splitlines(), key=len))
        if max_line_length > 5000 :
            # line too long, dont search it
            return
        for regex_id, regex in self.re_script.iteritems() :
            match = regex.finditer(data)
            try :
                while True :
                    m = match.next().group(0)
                    if m not in self.scripts :  # Count every identical match only once
                        if regex_id == 0 :
                            self.script_count[SHELL_RISK]+=1
                        elif regex_id in [1,2,3] :
                            self.script_count[SHELL_INSTALL_RISK]+=1
                        elif regex_id in [4,5,6,7] :
                            self.script_count[SHELL_PRIVILEGE_RISK]+=1
                        elif regex_id in [8,9,10] :
                            self.script_count[SHELL_OTHER_RISK]+=1
                    self.scripts.append(m)
                    self.scripts_files.append(file)
            except StopIteration, e :
                pass
        
    def _search_url(self, data, file) :
        """
            Apply regular expression looking for url
        """
        max_line_length = len(max(data.splitlines(), key=len))
        if max_line_length > 10000 :
            # line too long, dont search it
            #print "    file: "+file+" lines:%d"%(max_line_length)
            return
        #Valid URLs
        match = self.re_url1.finditer(data)
        while True :
            try : 
                m = match.next()
                m_tot = m.group(0)
                m_domain = m.group("domain")
                if (self.re_url_known.search(m_tot) is None
                and m_tot not in self.urls) :
                    self.urls.append(m_tot)
                    self.urls_domains.append(m_domain)
                    self.urls_files.append(file)
            except StopIteration, e :
                break
        #Parametrical and escaped URLs       
        match = self.re_url2.finditer(data)
        while True :
            try :
                m = match.next()
                m_tot = m.group(0)
                m_domain = m.group("domain")
                if (self.re_url_known.search(m_tot) is None
                and m_tot not in self.urls
                and m_tot not in self.urls2) :
                    self.urls2.append(m_tot)
                    self.urls2_domains.append(m_domain)
                    self.urls2_files.append(file)
            except StopIteration, e :
                break
                
    def _search_sms(self, data, file) :
        """
            Apply regular expression looking for sms short codes
        """
        match = self.re_sms1.finditer(data)
        try :
            while True :
                m = match.next().group(0)
                self.numbers.append(str(m))
                self.numbers_files.append(file)
        except StopIteration, e :
            pass
            
    def report(self, outputstream=sys.__stdout__) :
        """
            Print a detailed report after the apk has been analysed
            @param outputstream : can be used to redirect the output to a file
                    e.g.: outputstream = open('/home/giova/log.txt','w')
        """
        sys.stdout = outputstream
        if self.analysis_time == 0 :
            print "File not analysed yet; call method analyse_files"
            return
            
        print "[Info]"
        print "------"
        if self.path == "" :
            print "File path:\t(not available)"
        else :
            print "File path:\t" + self.path
        print "MD5:\t\t" + self.checksum_md5
        print "SHA1:\t\t" + self.checksum_sha1
        print "SHA256:\t\t" + self.checksum_sha256
        print "Duration:\t%.3f s" % self.analysis_time
        print ""
        print "[Risk score]"
        print "------"
        print "Total risk score:\t%d" % self.get_risk_score()
        print "InfectedDex risk:\t%d" % self.risks[0]
        print "InfectedElf risk:\t%d" % self.risks[1]
        print "HiddenApk:\t\t\t%d" % self.risks[2]
        print "HiddenElf:\t\t\t%d" % self.risks[3]
        print "HiddenText:\t\t\t%d" % self.risks[4]
        print "EmbeddedApk risk:\t%d" % self.risks[5]
        print "Shell risk:\t\t\t%d" % self.risks[6]
        print "ShellInstall:\t\t%d" % self.risks[7]
        print "ShellPrivilege:\t\t%d" % self.risks[8]
        print "ShellOther:\t\t\t%d" % self.risks[9]
        print ""
        print "[Files types]"
        print "------"
        for k,v in self.get_types_count().iteritems() :
            print k + ":\t%d" % v  
        print ""
        print "[Embedded apk]"
        print "------"
        for apk in self.get_apk() :
            print apk   
        print ""
        print "[Infected files]"
        print "------"
        print "From http://www.team-cymru.org/Services/MHR:"
        if self._is_mhr_reachable() == True :
            for file,result in self.get_detection_rate(self.get_dex_checksum()).iteritems() :
                print file + ":\t" + str(result) + "% detection rate"
            for file,result in self.get_detection_rate(self.get_elf_checksum()).iteritems() :
                print file + ":\t" + str(result) + "% detection rate"
        else :
            print " (the Malware Hash Registry is not reachable)"
        files = self.get_elf_infected(self.get_elf_checksum())
        if len(files)>0 :
            print "From known exploits:" 
        for file,malware in files.iteritems() :
            print file + ":\t", malware
        print ""
        print "[Suspect files]"
        print "------"
        files = self.get_suspect_files()
        for f,d in files["apk"].iteritems():
            print f + ":\t" + d
        for f,d in files["elf"].iteritems():
            print f + ":\t" + d
        for f,d in files["txt"].iteritems():
            print f + ":\t" + d
        print ""
        print "[Shell commands]"
        print "------"
        scripts, scripts_files = self.get_scripts()
        i = 0
        while i<len(scripts) :
            print scripts_files[i] + ":\t" + scripts[i]
            i+=1
        print ""
        print "[Urls]"
        print "------"
        urls, domains, urls_files = self.get_urls()
        i = 0
        while i<len(urls) :
            print urls_files[i] + ":\t" + urls[i]
            i+=1
        urls, domains, urls_files = self.get_urls_encoded()
        if len(urls)>0 :
            print "Encoded URLs:"
            i = 0
            while i<len(urls) :
                print urls_files[i] + ":\t" + urls[i]
                i+=1    
        print ""
        print "[Possible phone numbers]"
        print "------"
        numbers, numbers_files = self.get_numbers()
        i = 0
        while i<len(numbers) :
            print numbers_files[i] + ":\t" + numbers[i]
            i+=1
        sys.stdout=sys.__stdout__ 

    
#################################RISK###########################################
SYSTEM = None
class RiskIndicator :

    def __init__(self) :
        global SYSTEM

        if SYSTEM == None :
            SYSTEM = self._create_system_risk()            
    def get_risk(self, risks) :
        input_val = {}
        input_val['input_InfectedDex_Risk'] = risks[ INFECTED_DEX_RISK ]
        input_val['input_InfectedElf_Risk'] = risks[ INFECTED_ELF_RISK ]
        input_val['input_HiddenApk_Risk'] = risks[ HIDDEN_APK_RISK ]
        input_val['input_HiddenElf_Risk'] = risks[ HIDDEN_ELF_RISK ]
        input_val['input_HiddenText_Risk'] = risks[ HIDDEN_TXT_RISK ]
        input_val['input_EmbeddedApk_Risk'] = risks[ EMBEDDED_APK ]
        input_val['input_Shell_Risk'] = risks[ SHELL_RISK ]
        input_val['input_ShellInstall_Risk'] = risks[ SHELL_INSTALL_RISK ]
        input_val['input_ShellPrivilege_Risk'] = risks[ SHELL_PRIVILEGE_RISK ]
        input_val['input_ShellOther_Risk'] = risks[ SHELL_OTHER_RISK ]
        
        output_values = {"output_malware_risk" : 0}
    
        SYSTEM.calculate(input=input_val, output=output_values)
        return output_values["output_malware_risk"]

    def _create_system_risk(self) :
        try :
            import fuzzy
        except ImportError :
            error("please install pyfuzzy to use this module !")

        import fuzzy.System
        import fuzzy.InputVariable
        import fuzzy.fuzzify.Plain
        import fuzzy.OutputVariable
        import fuzzy.defuzzify.COGS
        import fuzzy.defuzzify.COG
        import fuzzy.defuzzify.MaxRight
        import fuzzy.defuzzify.MaxLeft
        import fuzzy.defuzzify.LM
        import fuzzy.set.Polygon
        import fuzzy.set.Singleton
        import fuzzy.Adjective
        import fuzzy.operator.Input
        import fuzzy.operator.Compound
        import fuzzy.norm.Min
        import fuzzy.norm.Max
        import fuzzy.norm.FuzzyAnd
        import fuzzy.norm.FuzzyOr
        import fuzzy.Rule
        import fuzzy.defuzzify.Dict

        system = fuzzy.System.System()
        input_InfectedDex_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_InfectedElf_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_HiddenApk_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_HiddenElf_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_HiddenText_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_EmbeddedApk_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_Shell_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_ShellInstall_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_ShellPrivilege_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        input_ShellOther_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
        
        # Input variables
        
            # InfectedDex Risk
        system.variables["input_InfectedDex_Risk"] = input_InfectedDex_Risk
        input_InfectedDex_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_InfectedDex_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # InfectedElf Risk
        system.variables["input_InfectedElf_Risk"] = input_InfectedElf_Risk
        input_InfectedElf_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_InfectedElf_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # HiddenApk Risk
        system.variables["input_HiddenApk_Risk"] = input_HiddenApk_Risk
        input_HiddenApk_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_HiddenApk_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # HiddenElf Risk
        system.variables["input_HiddenElf_Risk"] = input_HiddenElf_Risk
        input_HiddenElf_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_HiddenElf_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # HiddenText Risk
        system.variables["input_HiddenText_Risk"] = input_HiddenText_Risk
        input_HiddenText_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 1.0)]) )
        input_HiddenText_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
         # EmbeddedApk Risk
        system.variables["input_EmbeddedApk_Risk"] = input_EmbeddedApk_Risk
        input_EmbeddedApk_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_EmbeddedApk_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # Shell Risk
        system.variables["input_Shell_Risk"] = input_Shell_Risk
        input_Shell_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_Shell_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # ShellInstall Risk
        system.variables["input_ShellInstall_Risk"] = input_ShellInstall_Risk
        input_ShellInstall_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_ShellInstall_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # ShellPrivilege Risk
        system.variables["input_ShellPrivilege_Risk"] = input_ShellPrivilege_Risk
        input_ShellPrivilege_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_ShellPrivilege_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
            # ShellOther Risk
        system.variables["input_ShellOther_Risk"] = input_ShellOther_Risk
        input_ShellOther_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 0.0)]) )
        input_ShellOther_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0), (1.0, 1.0)]) )
        
        # Output variables
        output_malware_risk = fuzzy.OutputVariable.OutputVariable(
                                defuzzify=fuzzy.defuzzify.COGS.COGS(),
                                description="malware risk",
                                min=0.0,max=100.0,
                            )
        
        output_malware_risk.adjectives[NULL_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(0.0))
        output_malware_risk.adjectives[AVERAGE_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(30.0))
        output_malware_risk.adjectives[HIGH_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(70.0))
        output_malware_risk.adjectives[UNACCEPTABLE_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(100.0))
        system.variables["output_malware_risk"] = output_malware_risk
        
        # Rules
        #RULE 1: IF input_InfectedDex_Risk IS High THEN output_risk_malware IS Unacceptable;
        system.rules["r1"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
            operator = fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[HIGH_RISK] )
        )  
        #RULE 2: IF input_InfectedElf_Risk IS High THEN output_risk_malware IS Unacceptable;
        system.rules["r2"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
            operator = fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[HIGH_RISK] )
        )
        #RULE 3: IF input_HiddenApk_Risk IS High AND input_HiddenElf_Risk IS High THEN output_risk_malware IS Unacceptable;
        system.rules["r3"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[HIGH_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[HIGH_RISK] ),
            )
        )        
        #RULE 4: IF input_HiddenElf_Risk IS High AND input_ShellPrivilege_Risk IS High THEN output_risk_malware IS Unacceptable;
        system.rules["r4"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[HIGH_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellPrivilege_Risk"].adjectives[HIGH_RISK] )
            )
        )
        #RULE 5: IF input_HiddenApk_Risk IS High AND input_ShellInstall_Risk IS High THEN output_risk_malware IS Unacceptable;
        system.rules["r5"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[HIGH_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellInstall_Risk"].adjectives[HIGH_RISK] )
            )
        )
        #RULE 6: IF input_HiddenElf_Risk IS High AND input_ShellPrivilege_Risk IS Low THEN output_risk_malware IS High;
        system.rules["r6"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[HIGH_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellPrivilege_Risk"].adjectives[LOW_RISK] ),
                #Use only if there are not more dangerous factors
                fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[LOW_RISK] )
            )
        )
        #RULE 7: IF input_HiddenApk_Risk IS High AND input_ShellInstall_Risk IS Low THEN output_risk_malware IS High;
        system.rules["r7"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[HIGH_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellInstall_Risk"].adjectives[LOW_RISK] ),
                #Use only if there are not more dangerous factors
                fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[LOW_RISK] )
            )
        )
        #RULE 8: IF (input_Shell_Risk OR input_ShellInstall_Risk OR input_ShellPrivilege_Risk OR input_ShellOther_Risk IS High) AND input_HiddenText_Risk IS High THEN output_risk_malware IS High;
        system.rules["r8"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenText_Risk"].adjectives[HIGH_RISK] ),
                fuzzy.operator.Compound.Compound(
                    fuzzy.norm.Max.Max(),
                    fuzzy.operator.Input.Input(system.variables["input_Shell_Risk"].adjectives[HIGH_RISK] ),
                    fuzzy.operator.Input.Input(system.variables["input_ShellInstall_Risk"].adjectives[HIGH_RISK] ),
                    fuzzy.operator.Input.Input(system.variables["input_ShellPrivilege_Risk"].adjectives[HIGH_RISK] ),
                    fuzzy.operator.Input.Input(system.variables["input_ShellOther_Risk"].adjectives[HIGH_RISK] )
                ),
                #Use only if there are not more dangerous factors
                fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[LOW_RISK] )           
            )
        )
        #RULE 9: IF (input_Shell_Risk OR input_ShellInstall_Risk OR input_ShellPrivilege_Risk OR input_ShellOther_Risk IS High) AND input_HiddenText_Risk IS Low THEN output_risk_malware IS Average;
        system.rules["r9"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_HiddenText_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Compound.Compound(
                    fuzzy.norm.Max.Max(),
                    fuzzy.operator.Input.Input(system.variables["input_Shell_Risk"].adjectives[HIGH_RISK] ),
                    fuzzy.operator.Input.Input(system.variables["input_ShellInstall_Risk"].adjectives[HIGH_RISK] ),
                    fuzzy.operator.Input.Input(system.variables["input_ShellPrivilege_Risk"].adjectives[HIGH_RISK] ),
                    fuzzy.operator.Input.Input(system.variables["input_ShellOther_Risk"].adjectives[HIGH_RISK] )
                ),
                #Use only if there are not more dangerous factors
                fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[LOW_RISK] )
            )
        )
        #RULE 10: IF input_EmbeddedApk_Risk IS High THEN output_risk_malware IS Average;
        system.rules["r10"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_EmbeddedApk_Risk"].adjectives[HIGH_RISK] ),
                #Use only if there are not more dangerous factors
                fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[LOW_RISK] )
            )
        )
        #RULE 11: IF * IS Low AND HiddenText IS * THEN output_risk_malware IS Null;
        system.rules["r11"] = fuzzy.Rule.Rule(
            adjective = [system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
            operator = fuzzy.operator.Compound.Compound(
                fuzzy.norm.Min.Min(),
                fuzzy.operator.Input.Input(system.variables["input_InfectedDex_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_InfectedElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenApk_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_HiddenElf_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_EmbeddedApk_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_Shell_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellInstall_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellPrivilege_Risk"].adjectives[LOW_RISK] ),
                fuzzy.operator.Input.Input(system.variables["input_ShellOther_Risk"].adjectives[LOW_RISK] )
            )
        )
        return system
