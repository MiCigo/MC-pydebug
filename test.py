# _*_ coding:utf-8 _*_

import mc_debugger
from mc_debugger_defines import *

debugger = mc_debugger.debugger()

pid = raw_input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve("msvcrt.dll", "printf")

print "Address of printf: 0x%08x" % printf_address

debugger.bp_set_mem(printf_address,10)

debugger.run()

# #提取列表中每一个线程的相应信息
# list = debugger.enumerate_threads()
# 
# for thread in list:
#     
#     thread_context = debugger.get_thread_context(thread)
#     
#     #寄存器信息
#     print "Dumpling registers for thread ID: 0x%08x" % thread
#     print "EIP: 0x%08x" % thread_context.Eip
#     print "ESP: 0x%08x" % thread_context.Esp
#     print "EBP: 0x%08x" % thread_context.Ebp
#     print "EAX: 0x%08x" % thread_context.Eax
#     print "EBX: 0x%08x" % thread_context.Ebx
#     print "ECX: 0x%08x" % thread_context.Ecx
#     print "EDX: 0x%08x" % thread_context.Edx
#     print("\n")

debugger.deatch()
#debugger.load("C:\\WINDOWS\\system32\\calc.exe")

'''
Created on Mar 1, 2016

@author: Micih
'''
