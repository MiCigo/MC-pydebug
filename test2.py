# _*_ coding:utf-8 _*_

from ctypes import *
from pydbg import *
from pydbg.defines import *

import struct
import random

from mc_debugger_defines import DBG_CONTINUE

def printf_randomizer(dbg):
    
    parameter_addr = dbg.context.Esp + 0x8
    counter = dbg.read_process_memory(parameter_addr)
    
    counter = struct.unpack("L",counter)[0]
    print ("Counter: %d" % int(counter))
    
    random_counter = random.randint(1,100)
    random_counter = struct.pack("L",random_counter)[0]
    
    dbg.write_process_memory(parameter_addr,random_counter)
    
    return DBG_CONTINUE

dbg = pydbg()

pid = raw_input("Enter the pid:")

dbg.attach(int(pid))

printf_address = dbg.func_resolve("msvcrt","printf")
dbg.bp_set(printf_address,description = "printf_address",handler = printf_address)

dbg.run()


'''
Created on Mar 2, 2016

@author: Micih
'''
