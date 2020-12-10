import requests,random,json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bane.payloads import ua
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
def wp_users_list(u,path='/wp-json/wp/v2/users',timeout=10,user_agent=None,cookie=None,proxy=None):
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
    users.append({'slug':a[x]['slug'],'name':a[x]['name']})
   return (users,a)
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
 
def wp_posts_list(u,path='/wp-json/wp/v2/posts',timeout=10,user_agent=None,cookie=None,proxy=None):
 '''
   this function is to get WP posts
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
  if ('{"id":'in r.text) and('"date":"' in r.text):
   return json.loads(r.text)
 except Exception as e:
  pass
 
def wp_post(u,path='/wp-json/wp/v2/posts/',post=1,timeout=10,user_agent=None,cookie=None,proxy=None):
 '''
   this function is to return all informations about a WP post with a given index integer
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
 u+=path+str(post)
 try:
  r=requests.get(u, headers = hed,proxies=proxy,timeout=timeout, verify=False)
  if ('{"id":'in r.text) and('"date":"' in r.text):
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
          print("[+]Username found: {} | ID: {}".format(a,x))
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
  return r.split('<meta name="generator" content="')[1].split('"')[0].strip()
 except:
  pass
