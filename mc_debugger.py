# _*_ coding:utf-8 _*_

from ctypes import *
from mc_debugger_defines import *
from _subprocess import INFINITE
from _multiprocessing import win32
from itertools import count

import sys
import time

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process  = None
        self.pid        = None
        self.debugger_active = False
        self.h_thread   = None
        self.context    = None
        self.breakpoints    = {}
        self.exception  = None
        self.exception_address = None
        self.first_breakpoint = True
        self.hardware_breakpoints = {}
        
        #系统默认内存页大小设定
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        #内存保护页与内存断点
        self.guarder_pages = []
        self.memory_breakpoints = {}
    
    def load(self,path_to_exe):
        
        creation_flags = DEBUG_PROCESS
        
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        
        startupinfo.cb = sizeof(startupinfo)
        
        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            print "We have Successefully launched the process!"
            print "PID: %d" % process_information.dwProcessId
            
            self.h_process  = self.open_process(process_information.dwProcessId)
        else:
            print "Error: 0x%08x." % kernel32.GetLastError()
            
        
    def open_process(self,pid):
        
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid) 
        
        return h_process
    
    def attach(self,pid):
        
        self.h_process = self.open_process(pid)
        
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid             = int(pid)

        else:
            print "Unable to attach to the process!"
            
    def run(self):
        
        while self.debugger_active ==True:
            self.get_debug_event()
        
    def get_debug_event(self):
        
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):
            
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.debug_event = debug_event
            
            print("Event Code: %d Thread ID: %d Process ID: %d ") % (debug_event.dwDebugEventCode,debug_event.dwThreadId,debug_event.dwProcessId)

            #若代码显示为异常事件，则进一步检测其确切的类型
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:               
                #获取异常代码
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access Violation Detected."
                
                #检测到断点，调用相应内部处理例程
                #软断点
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
            
                #内存断点
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected.")
                
                #硬件断点
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    print "Single Stepping."
                    self.exception_handler_single_step()

#             raw_input("press a key to continue...")
#             self.debugger_active = False
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,continue_status)

        
    def deatch(self):
        
        if kernel32.DebugActiveProcessStop(self.pid):
            print "Finished debugging. Exiting..."
            return True
        else:
            print "There was an error: 0x%08x." %kernel32.GetLastError() 
            return False
    
    def open_thread(self,thread_id):
        
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,None,thread_id)
        
        if h_thread is not None:
            return h_thread
        else:
            print "Could not obtain a valid thread handle."
            return False
    
    def enumerate_threads(self):
        
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot    = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,self.pid)
        
        if snapshot is not None:
            
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot,byref(thread_entry))
            
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                    
                success = kernel32.Thread32Next(snapshot,byref(thread_entry))
                    
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
    
    def get_thread_context (self, thread_id=None, h_thread=None):
        
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)
            
        if kernel32.GetThreadContext(self.h_thread,byref(context)):
            return context
        else:
            return False
    
    def exception_handler_breakpoint(self):
        
        print "Inside the breakpoint handler."
        print "Exception address: 0x%08x" % self.exception_address
        
        if not self.breakpoints.has_key(self.exception_address):
            
            #第一个断点是Win自身驱动出发的异常断点，进程继续执行。
            if self.first_breakpoint == True:
                self.first_breakpoint = False
                print "Hit the first breakpoints!"
                return DBG_CONTINUE
        
        else:
            print "Hit user defined breakpoints!"
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])
            
            self.context = self.get_thread_context(h_thread = self.h_thread)
            self.context.Eip -= 1
            
            kernel32.SetThreadContext(self.h_thread,byref(self.context))
            
            continue_status = DBG_CONTINUE
            
        return continue_status
    
    def read_process_memory(self,address,length):
        
        data    = ""
        read_buf = create_string_buffer(length)
        count   = c_ulong(0)
        
        kernel32.ReadProcessMemory(self.h_process,address,read_buf,length,byref(count))
        data    = read_buf.raw
        
        return data
    
    def write_process_memory(self,address,data):
        
        count   = c_ulong(0)
        length  = len(data)
        
        c_data  = c_char_p(data[count.value:])
        
        if not kernel32.WriteProcessMemory(self.h_process,address,c_data,length,byref(count)):
            return False
        else:
            return True
    
    def bp_set(self,address):
        
        print "Set the breakpoint at: 0x%08x" %address
        if not self.breakpoints.has_key(address):
            
            old_protect = c_ulong(0)
            kernel32.VirtualProtectEx(self.h_process, address, 1, PAGE_EXECUTE_READWRITE, byref(old_protect))
            #备份这个内存地址上的原有字符
            original_byte = self.read_process_memory(address, 1)
            if original_byte != False:
                
                #写入一个INT3中断指令，其操作码为0xCC
                if self.write_process_memory(address,"\xCC"):
                
                    #将设下的断点记录在一个内部的断点列表中
                    self.breakpoints[address] = (original_byte)
                    return True
                
            else:
                return False
        
    
    def func_resolve(self,dll,function):
        
        handle  = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        return address         
    
    def bp_set_hw(self,address,length,condition):
        
        #检测硬件断点长度是否有效
        if length not in (1,2,4):
            return False
        else:
            length -= 1
        
        #检测硬件断点的触发条件是否有效
        if condition not in (HW_ACCESS,HW_EXECUTE,HW_WRITE):
            return False
        
        #检测是否存在空置的调试寄存器
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False
        
        #所有线程下设置
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            
            #设置DR7标志位激活断点
            context.Dr7 |= 1 << (available * 2)
            
            #在空置的寄存器中写入断点
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available -- 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address
        
            #硬件断点触发条件
            context.Dr7 |= condition << ((available * 4) + 16)
        
            #硬件断点长度
            context.Dr7 |= length << ((available * 4) + 18)
        
            #改动后线程的上下文环境信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
        
        #更新内部硬件断点列表
        self.hardware_breakpoints[available] = (address,length,condition)
        
        return True
        
    
    def exception_handler_single_step(self):
        
        print "Exception address: 0x%08x" % self.exception_address
         
        #判断该单步事件是否由一个硬件断点触发，若是则捕获这个断点
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x3 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            #INT1中断并非由一个硬件断点导致
            continue_status = DBG_EXCEPTION_NOT_HANDLED
        
        #从断点列表移除这个断点
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
        
        print ("Hardware breakpoint removed.")
        return continue_status
    
    def bp_del_hw(self,slot):
        
        for thread_id in self.enumerate_threads():
            
            context = self.get_thread_context(thread_id=thread_id)
            
            #重设标志位移除硬件断点
            context.Dr7 &= ~(1 << (slot * 2))
            
            #将断点地址清零
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000
            
            #清空断点触发条件标志位
            context.Dr7 &= ~(3 << (slot * 4) + 16)
            #清空断点长度标志位
            context.Dr7 &= ~(3 << (slot * 4) + 18)
            #提交移除断点后的线程上下文信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
            
        #从内部断点列表中删除
        del self.hardware_breakpoints[slot]
        
        return True
    
    def bp_set_mem (self,address,size):
        
        mbi = MEMORY_BASIC_INFORMATION()
        
        #校验mbi结构体完整性
        if kernel32.VirtualQueryEx(self.h_process,address,byref(mbi),sizeof(mbi) < sizeof(mbi)):
            return False
        
        current_page = mbi.BaseAddress
        #对内存断点区域所覆盖到的所有内存页设置权限
        while current_page <= address + size:
            
            #将此内存页记录在列表中，与操作系统或debuge进程自设的保护页区别开来
            self.guarder_pages.append(current_page)
            
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process,current_page,size,mbi.Protect | PAGE_GUARD,byref(old_protection)):
                return False
            
            #以系统所设的内存页尺寸作为增长单位来递增我们的内存断点区域
            current_page += self.page_size
        
        #将此内存断点记录与全局性列表中
        self.memory_breakpoints[address] = {address,size,mbi}
        
        return True
      
'''
Created on Mar 1, 2016
version progress:
    bate0.1:调用一个进程，输出（PID）。
    bate0.2:支持进程附加与脱离操作，创建一个进程并获取Handle值，构建初步循环调试结构用于处理调试事件。
    bate0.3:增加线程枚举(TID)
    bate0.4:增加寄存器信息获取
    bate0.5:增加调试事件处理例程
    bate0.6:软件断点（未知Bug已解决)
    bare0.7:硬件断点 (还有Bug)
    bate0.8:内存断点
    bate0.9:测试
@author: Micih
'''
