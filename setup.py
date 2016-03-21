# _*_ coding:utf-8 _*_

from distutils.core import setup
import py2exe

setup(console = ['backdoor.py'],options = {'py2exe':{'bundle_files':1}},zipfile = None,)

'''
Created on Mar 10, 2016

@author: Micih
'''
