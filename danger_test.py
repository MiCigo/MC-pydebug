# _*_ coding:utf-8 _*_

from pydbg import *
from pydbg.defines import *

import utils

#程序复位至快照之后可以单步执行指令的次数
MAX_INSTRUCTIONS = 20

dangerous_functions = {"strcpy":"msvcrt.dll","strncpy":"msvcrt.dll","sprintf":"msvcrt.dll","vsprintf":"msvcrt.dll"}

dangerous_functions_revolved = {}
crash_encountered   = False
instruction_count   = 0
def danger_handler(dbg):
    
    esp_offset = 0
    print "Hit %s" & dangerous_functions_revolved[dbg.content.Eip]
    print "-------------------------------------------------------"
    
    while esp_offset <= 20:
        parameter = dbg.smart_dereference(dbg.context.Esp + esp_offset)
        print "[ESP + %d] => %s" % (esp_offset,parameter)
        esp_offset += 4
        
    print "--------------------------------------------------------"
    
    dbg.suspend_all_threads()
    dbg.process_snapshot()
    dbg.resume_all_threads()
    
    return DBG_CONTINUE

def access_violation_handler(dbg):
    global crash_encountered
    
    if dbg.dbg.u.Exception.dwFirstChance:
        return DBG_EXCEPTION_NOT_HANDLED
    
    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)
    print crash_bin.crash_synopsis()
    
    if crash_encountered == False:
        dbg.suspend_all_threads()
        dbg.process_restore()
        crash_encountered = True
        
        for thread_id in dbg.enumerate_threads():
            print " Setting single step for thread: 0x%08x" % thread_id
        
            h_thread = dbg.open_thread(thread_id)
            dbg.single_step(True.h_thread)
            dbg.close_handle(h_thread)
        
            dbg.resume_all_threads()
    
            return DBG_CONTINUE
    else:
        dbg.terminate_process()
    
    return DBG_EXCEPTION_NOT_HANDLED

def single_step_handler(dbg):
    global instruction_count
    global crash_encountered
    
    if crash_encountered:
        if instruction_count == MAX_INSTRUCTIONS:
            dbg.single_step(False)
            return DBG_CONTINUE
        else:
            

    
'''
Created on Mar 5, 2016

@author: Micih
'''
