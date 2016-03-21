# _*_ coding:utf-8 _*_

import sys
from ctypes import *

PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM = (0x1000 | 0x2000)

kernel32 = windll.kernel32
pid = sys.argv[1]
dll_path = sys.argv[2]
dll_len = len(dll_path)

h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

if not h_process:
    print "Couldn't acquire a handle to PID: %s" % pid
    sys.exit()
    #为DLL路径字符串分配内存空间
    arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)
    #写入DLL路径字符串
    writen = c_int(0)
    kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(writen))
    #解析API函数LoadLibraryA所在内存地址
    h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
    
    #创建远程线程，将线程入口地址设置为LoadLibraryA所在地址，并以一个指向DLL路径字符串的指针作为唯一参数
    thread_id = c_ulong(0)
    
    if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
        print "Failed to inject the DLL. Exiting."
        sys.exit(0)
    
    print "Remote thread with ID 0x%08x created" % thread_id.value
    
    #创建完成

    

'''
Created on Mar 12, 2016

@author: Micih
'''
