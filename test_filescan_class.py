#!/usr/bin/env python

import sys, os

from time import time
from optparse import OptionParser
from androguard.core.analysis.filescan import *


option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-d', '--directory'), 'help' : 'directory : examine all apks from this directory', 'nargs' : 1 }

options = [option_0, option_1]


def test(apk) :
    
    try :
        analysis_time = 0
        start = time()
        file_scan = FileScan(apk)
        risk_values = file_scan.analyze_files()
        analysis_time = time() - start
        
        # Print the report to a file
        report_file = open("/home/giova/tools/filescan/reports/" + file_scan.get_sha1() + ".filescan.txt",'w')
        file_scan.report(report_file)
        report_file.close()
        
        # Print the risk values in CSV notation
        string = "\""+os.path.basename(apk)+"\""
        string += ";"+file_scan.get_sha1()
        string += ";"+str(round(analysis_time,3)) #.replace(".", ",")
        string += ";"+str(file_scan.get_risk_score())
        string += ";"+str(risk_values[0])
        string += ";"+str(risk_values[1])
        string += ";"+str(risk_values[2])
        string += ";"+str(risk_values[3])
        string += ";"+str(risk_values[4])
        string += ";"+str(risk_values[5])
        string += ";"+str(risk_values[6])
        string += ";"+str(risk_values[7])
        string += ";"+str(risk_values[8])
        string += ";"+str(risk_values[9])
        print string
        #"""
 
 
        """#####################################################################
		# Print a complete report
        file_scan.report()
		
		# Print the report to a file
        report_file = open("/home/giova/tools/filescan/reports/" + file_scan.get_sha1() + ".filescan.txt",'w')
        file_scan.report(report_file)
        report_file.close()
                                                                                                 
        # Print the final risk value
        print "RISK VALUE"
        print "   > Risk =", file_scan.get_risk_score()
        
        # Print the partial risk values
        print "RISK VALUES"
        print "   > InfectedDex =", risk_values[0]
        print "   > InfectedElf =", risk_values[1]
        print "   > HiddenApk =", risk_values[2]
        print "   > HiddenElf =", risk_values[3]
        print "   > HiddenText =", risk_values[4]
        print "   > EmbeddedApk =", risk_values[5]
        print "   > Shell =", risk_values[6]
        print "   > ShellInstall =", risk_values[7]
        print "   > ShellPrivilege =", risk_values[8]
        print "   > ShellOther =", risk_values[9]
        
        # Print the risk values in CSV notation
        string = "\""+os.path.basename(apk)+"\""
        string += ";"+file_scan.get_sha1()
        string += ";"+str(file_scan.get_risk_score())
        string += ";"+str(risk_values[0])
        string += ";"+str(risk_values[1])
        string += ";"+str(risk_values[2])
        string += ";"+str(risk_values[3])
        string += ";"+str(risk_values[4])
        string += ";"+str(risk_values[5])
        string += ";"+str(risk_values[6])
        string += ";"+str(risk_values[7])
        string += ";"+str(risk_values[8])
        string += ";"+str(risk_values[9])
        print string        
        
        # Query the Hash Malware Registry (http://www.team-cymru.org/Services/MHR/)
        # and show the detection rate for every dex and elf file
        print "HMR DETECTION RATES"
        for file,result in file_scan.get_dex_detection_rate().iteritems() :
            print "   >", "DEX Detection rate for %s = %s%%" %(file, result)
        for file,result in file_scan.get_elf_detection_rate().iteritems() :
            print "   >", "ELF Detection rate for %s = %s%%" %(file, result)
            
        # Print a list of known malicious binary files (ELF)
        files = file_scan.get_elf_infected()
        if not len(files)==0 :
            print "KNOWN MALWARE"
        for file,malware in files.iteritems() :
            print "   >", file, "is:", malware
            
        # Print a list of the interesting files with changed extension
        print "SUSPICIOUS EXTENSIONS"
        for file,descr in file_scan.suspicious_extensions().iteritems() :
            print "   > " + file + " -> " + descr
            
        # Print a list of file which contains shell commands, and the commands found inside them
        scripts, scripts_files = file_scan.get_scripts()
        if not len(scripts)==0 :
            print "COMMANDS BY FILES"
        i = 0
        while i<len(scripts) :
            print "   >", scripts_files[i], ">", scripts[i]
            i+=1
        
        # Print the time required to analyse the apk file
        print "ANALYSIS TIME"
        print "   >", str(file_scan.get_analysis_time())
        
        # Print the sha1 of the apk
        print "SHA1 CHECKSUM"
        print "   >", file_scan.get_sha1()
        
        # Print a list of every file in the archive
        print "FILES LIST"
        for f in file_scan.get_files_list() :
            print "   >", f 
        
        # Print a list (by type) of the number of files found in the archive
        print "FILES BY TYPES"
        for k,v in file_scan.get_types_count().iteritems() :
            print "   >", k, "=", v
             
        # Print a list of apk files found in the archive
        print "APK LIST"
        for apk in file_scan.get_apk() :
            print "   >", apk      
             
        # Print the checksum (computed with 6 different hash functions) for every dex file
        print "DEX CHECKSUMS"
        dex_md5 = file_scan.get_dex_checksum("md5");
        dex_sha1 = file_scan.get_dex_checksum("sha1");
        dex_sha224 = file_scan.get_dex_checksum("sha224");
        dex_sha256 = file_scan.get_dex_checksum("sha256");
        dex_sha384 = file_scan.get_dex_checksum("sha384");
        dex_sha512 = file_scan.get_dex_checksum("sha512");
        for file in dex_md5.keys() :
            print "   >", file
            print "   >", " MD5:   ", dex_md5[file]
            print "   >", " SHA1:  ", dex_sha1[file]
            print "   >", " SHA224:", dex_sha224[file]
            print "   >", " SHA256:", dex_sha256[file]
            print "   >", " SHA384:", dex_sha384[file]
            print "   >", " SHA512:", dex_sha512[file]
        
        # Print the checksum (computed with 6 different hash functions) for every elf file
        print "ELF CHECKSUMS"
        elf_md5 = file_scan.get_elf_checksum("md5");
        elf_sha1 = file_scan.get_elf_checksum("sha1");
        elf_sha224 = file_scan.get_elf_checksum("sha224");
        elf_sha256 = file_scan.get_elf_checksum("sha256");
        elf_sha384 = file_scan.get_elf_checksum("sha384");
        elf_sha512 = file_scan.get_elf_checksum("sha512");
        for file in elf_md5.keys() :
            print "   >", file
            print "   >", " MD5:   ", elf_md5[file]
            print "   >", " SHA1:  ", elf_sha1[file]
            print "   >", " SHA224:", elf_sha224[file]
            print "   >", " SHA256:", elf_sha256[file]
            print "   >", " SHA384:", elf_sha384[file]
            print "   >", " SHA512:", elf_sha512[file]
            
        # Print a list of file which contains URLs, and the URLs found inside them
        urls, domains, urls_files = file_scan.get_urls(show_files=True)
        if not len(urls)==0 :
            print "URLS BY FILES"
        i = 0
        while i<len(urls) :
            print "   >", urls_files[i], ">", urls[i]
            i+=1
            
        # Print a list of file which contains encoded URLs, and the URLs found inside them
        urls, domains, urls_files = file_scan.get_urls_encoded(show_files=True)
        if not len(urls)==0 :
            print "URLS BY FILES"
        i = 0
        while i<len(urls) :
            print "   >", urls_files[i], ">", urls[i]
            i+=1
            
        # Print a list of file which contains phone numbers, and the phone numbers found inside them
        numbers, numbers_files = file_scan.get_numbers()
        if not len(numbers)==0 :
            print "PHONE NUMBERS BY FILES"
        i = 0
        while i<len(numbers) :
            print "   >", numbers_files[i], ">", numbers[i]
            i+=1
        #####################################################################"""
        
    except Exception, e:
        print "\"Exception raised (for apk:",apk+"):"+str(e)+"\"" 
    
    
def main(options, arguments) :
    
    if options.input is None and options.directory is None :
        print 'waiting for file(s) to analyze'
        return
        
    if options.input != None :
        test(options.input)
    else :
        dirList=os.listdir(options.directory)
        i = 0
        tot = len(dirList)
        for fname in dirList:
            i+=1
            if fname.lower().endswith(".apk") :
                # Print the apk name to stderr; this way normal output can be redirected to file,
                # while still having some output from the script in the shell
                print >> sys.stderr, fname, "\t(%d/%d)" %(i, tot)
                test(options.directory + fname)
                
            else :
                i-=1
                tot-=1

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
