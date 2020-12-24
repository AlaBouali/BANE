import requests,random,re,time,furl,sys
if  sys.version_info < (3,0):
 from urlparse import urlparse
else:
 from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import bs4
from bs4 import BeautifulSoup
from bane.payloads import *
def inputs(u,value=False,timeout=10,user_agent=None,bypass=False,proxy=None,cookie=None):
 '''
   this function is to get the names and values of input fields on a given webpage to scan.

   it takes 4 arguments:

   u: the page's link (http://...)
   value: (set by default to: False) to return the value of the fields set it to:True then the field's name and value will be string of 2 
   values sperated by ":"
   timeout: (set by default to: 10) timeout flag for the request
   bypass: (set by default to: False) to bypass anti-crawlers

  usage:

  >>>import bane
  >>>link='http://www.example.com'
  >>>bane.inputs(link)
  ['email','password','rememberme']
  >>>a=bane.inputs(link,value=True)
  ['email','password','rememberme:yes','rememberme:no']
  
 '''
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if proxy:
  proxy={'http':'http://'+proxy}
 if bypass==True:
  u+='#'
 if cookie:
  hea={'User-Agent': us,'Cookie':cookie}
 else:
  hea={'User-Agent': us}
 l=[]
 try:
  c=requests.get(u, headers = hea,proxies=proxy,timeout=timeout, verify=False).text
  soup= BeautifulSoup(c,'html.parser')
  p=soup.find_all('textarea')
  for r in p: 
    if r.has_attr('name'):
     s=r.get("name")
     v=r.get("value")
     if v==None:
      v=''
    if value==True:
     y=s+":"+v
    else:
     y=s
    if y not in l:
     l.append(y)
  p=soup.find_all('input')
  for r in p: 
    v=""
    if r.has_attr('name'):
     s=str(r)
     s=s.split('name="')[1].split(',')[0]
     s=s.split('"')[0].split(',')[0]
     if (r.has_attr('value') and (value==True)):
      v=str(r)
      v=v.split('value="')[1].split(',')[0]
      v=v.split('"')[0].split(',')[0]
    if value==True:
     y=s+":"+v
    else:
     y=s
    if y not in l:
     l.append(y)
 except Exception as e:
  pass
 return l
def forms(u,value=True,user_agent=None,timeout=10,bypass=False,proxy=None,cookie=None):
 '''
   same as "inputs" function but it works on forms input fields only
 '''
 if urlparse(u).path=='':
  u+="/"
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if proxy:
   proxy={'http':'http://'+proxy}
 if bypass==True:
   u+='#'
 if cookie:
   hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 l=[]
 fom=[]
 try:
  c=requests.get(u, headers = hea,proxies=proxy,timeout=timeout, verify=False).text
  soup= BeautifulSoup(c,'html.parser')
  i=soup.find_all('form')
  for f in i:
   ac=f.get('action')
   if not ac:
    ac=u
   """if len(ac)==0:
    ac=u
   if ac[0]=="/":
    url_o="/".join(u.split('/')[:-1])
    ac=url_o+ac
   if ac[:4]!="http":
    url_o="/".join(u.split('/')[:-1])
    ac=url_o+"/"+ac"""
   if ("://" not in ac):
      ur=u[:u.rfind('/')]
      if ac[0]=="/":
       ac=ac[1:len(ac)]
       print(ac)
      ac=ur+"/"+ac
   me=f.get('method')
   if not me :
    me="get"
   if len(me)==0:
    me="get"
   me=me.lower()
   p=f.find_all('textarea')
   for r in p: 
    if r.has_attr('name'):
     s=r.get("name")
     v=r.get("value")
     if v==None:
      v=''
    if value==True:
     y=s+":"+v
    else:
     y=s
    if y not in l:
     l.append(y)
   p=f.find_all('input')
   for r in p: 
    if r.has_attr('name'):
     s=r.get("name")
     v=r.get("value")
     if v==None:
      v=''
    if value==True:
     y=s+":"+v
    else:
     y=s
    if y not in l:
     l.append(y)
   fom.append({'inputs':l,'action':ac,'method':me}) 
   l=[]
 except Exception as e:
  pass
 return fom

def crawl(u,timeout=10,user_agent=None,bypass=False,proxy=None,cookie=None):
 '''
   this function is used to crawl any given link and returns a list of all available links on that webpage with ability to bypass anti-crawlers
   
   the function takes those arguments:
   
   u: the targeted link
   timeout: (set by default to 10) timeout flag for the request
   bypass: (set by default to False) option to bypass anti-crawlers by simply adding "#" to the end of the link :)

   usage:

   >>>import bane
   >>>url='http://www.example.com'
   >>>bane.crawl(url)
   
   >>>bane.crawl(url,bypass=True)
'''
 if urlparse(u).path=='':
  u+="/"
 if u.split("?")[0][-1]!="/" and '.' not in u.split("?")[0].rsplit('/', 1)[-1]:
    u=u.replace('?','/?')
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if proxy:
  proxy={'http':'http://'+proxy}
 h={}
 if bypass==True:
  u+='#'
 if cookie:
  hea={'User-Agent': us,'Cookie':cookie}
 else:
  hea={'User-Agent': us}
 try:
  c=requests.get(u, headers = hea,proxies=proxy,timeout=timeout, verify=False).text
  soup = BeautifulSoup(c,"html.parser")
  ur=u.replace(u.split("/")[-1],'')
  """if ur[-1]=='/':
   ur=ur[:-1]"""
  index_link=0
  for a in soup.find_all('a'):
   u=ur
   if a.has_attr('href'):
    try:
     txt=str(a).split('>')[1].split('<')[0].strip()
     a=str(a['href'])
     if ("://" not in a):
      if a[0]=="/":
       a=a[1:len(a)]
      a=u+a
     if (a not in h.values()) and (u in a):
      if (a!=u+"/") and (a!=u):
       h.update({index_link:(txt,a,urlparse(a).path,[ (x,furl.furl(a).args[x]) for x in furl.furl(a).args])})
       index_link+=1
    except Exception as e:
     pass
 except Exception as ex:
  pass
 return h

def media(u,timeout=10,user_agent=None,bypass=False,proxy=None,cookie=None):
 '''
   this funtion was made to collect the social media links related to the targeted link (facebook, twitter, instagram...).

   the function takes those arguments:
   
   u: the targeted link
   timeout: (set by default to 10) timeout flag for the request
   bypass: (set by default to False) option to bypass anti-crawlers by simply adding "#" to the end of the link :)

   usage:

   >>>import bane
   >>>url='http://www.example.com'
   >>>bane.media(url)
   
   >>>bane.media(url,bypass=True)
'''
 if urlparse(u).path=='':
  u+="/"
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if cookie:
   hea={'User-Agent': us,'Cookie':cookie}
 else:
   hea={'User-Agent': us}
 h={}
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
  if bypass==True:
   u+='#'
  if cookie:
   hea={'User-Agent': us,'Cookie':cookie}
  else:
   hea={'User-Agent': us}
  c=requests.get(u,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
  soup = BeautifulSoup(c,"html.parser")
  ul=u.split('://')[1].split('"')[0]
  ur=ul.replace("www.",'') 
  for a in soup.findAll('a'):
   try:
    if a.has_attr('href') and (u not in str(a)) and (ur not in str(a)) and ("://" in str(a)) :
     txt=str(a).split('>')[1].split('<')[0].strip()
     if a["href"] not in h:
      h.update({txt:a["href"]})
   except:
    pass
 except:
  pass
 return h

def subdomains_extract(u,timeout=10,user_agent=None,bypass=False,proxy=None,cookie=None):
 '''
   this function collects the subdomains found on the targeted webpage.

   the function takes those arguments:
   
   u: the targeted link
   timeout: (set by default to 10) timeout flag for the request
   bypass: (set by default to False) option to bypass anti-crawlers by simply adding "#" to the end of the link :)

   usage:

   >>>import bane
   >>>url='http://www.example.com'
   >>>bane.subdomains_extract(url)
   
   >>>bane.subdomains_extract(url,bypass=True)
'''
 if urlparse(u).path=='':
  u+="/"
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 if proxy:
  proxy={'http':'http://'+proxy}
 h=[]
 if cookie:
  hea={'User-Agent': us,'Cookie':cookie}
 else:
  hea={'User-Agent': us}
 try:
  if bypass==True:
   u+='#'
  c=requests.get(u, headers = hea,proxies=proxy,timeout=timeout, verify=False).text
  ul=u.split('://')[1].split('"')[0]
  soup = BeautifulSoup(c,"html.parser")
  for a in soup.findAll('a'):
   if a.has_attr('href') and (ul.replace("www",'') in str(a)) and (u not in str(a)):
    a=str(a)
    try:
     a=a.split('://')[1].split('"')[0]
     a=a.split('/')[0].split('"')[0]
     if a not in h:
      h.append(a)
    except Exception as e:
     pass
 except:
  pass
 return h
