# _*_ coding:utf-8 _*_

import sys

#读取DLL
fd = open(sys.argv[1],"rb")
dll_contents = fd.read()
fd.close()
print "Fileseize: %d" % len(dll_contents)

#将DLL写入ADS
fd = open("%s:%s" % ( sys.argv[2],sys.argv[1]),"wb")
fd.write(dll_contents)
fd.close


'''
Created on Mar 10, 2016

@author: Micih
'''
