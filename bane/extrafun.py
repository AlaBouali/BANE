import cgi,requests,os,random,re,hashlib,urllib,sys,cfscrape
from googlesearch import search
from bane.payloads import ua
from bane.hasher import *
if  sys.version_info < (3,0):
    import HTMLParser
else:
    import html.parser as HTMLParser
import bs4
from bs4 import BeautifulSoup
from bane.payloads import *

def clear_file(w):
 with open(w,'w'):
    pass
def delete_file(w):
 s=0
 if os.path.exists(w):
  os.remove(w)
  s+=1
 return s
def write_file(w,fi):
    with open(fi ,"a+") as f:
        f.write(w+'\n')
        return   
def read_file(w):
    with open(w ,"r") as f:
        return f.readlines()
def create_file(w):
    with open(w ,"a+") as f:
     pass   
def get_cf_cookie(domain,user_agent):
  try:
   s = cfscrape.create_scraper()
   c = s.get_cookie_string("http://"+domain,user_agent=user_agent)
   return {user_agent: str(c).split("'")[1].split("'")[0]}
  except:
   return {}
def HTB_invitation():
 try:
  r=requests.post('https://www.hackthebox.eu/api/invite/generate',headers={'User-Agent':random.choice(ua)},data={'':''}).text
  a=r.split('"code":"')[1].split('"')[0]
  return base64decode(a)
 except:
  return None
def facebook_id(u):
 try:
  r=requests.post('https://lookup-id.com/#',data={"fburl":u,"check":"Lookup"}).text
  return r.split('<p id="code-wrap"><span id="code">')[1].split('<')[0]
 except:
  return None
def check_file_virustotal(f,proxy=None,timeout=10):
 if proxy:
  proxy={'http':'http://'+proxy}
 s=sha256fl(f)
 u="https://www.virustotal.com/en/file/"+s+"/analysis/"
 try:
  r=requests.get(u,headers = {'User-Agent': random.choice(ua)},allow_redirects=False,proxies=proxy,timeout=timeout)
  if (r.status_code==302):
   return {"status": r.status_code,"reason":"File's signature wasn't recognized by VirusTotal.\nTry to upload the file manually if you want to make sure."}
  elif r.status_code==200:
   w=""
   for x in r.text:
    if (len(w)<1001):
     w+=x
   w=w[931:len(w)-3].strip()
   w=w.replace("\n ","")
   return {"status":r.status_code,"reason":w}
  else:
   return {"status":r.status_code,"reason":"something went wrong"}
 except Exception as e:
  return {"status":e,"reason":"error with the process"}
def google_dorking(q,max_results=100,language='en',start_from=1, stop_on=None,top_level_domain='com',pause=2):
 j=[]
 j+=search(q,num=max_results,lang=language,start=start_from, stop=stop_on,tld="com", pause=2)
 l=[]
 for x in j:
  if x not in l:
   l.append(x)
 return l
def escape_html(s):
 '''
   function to return escaped html string
 '''
 return cgi.escape(s,quote=True)
def unescape_html(s):
 '''
   function to return unescaped html string
 '''
 return HTMLParser.HTMLParser().unescape(s).encode("utf-8")
def webhint_report(ur,proxy=None,timeout=10):
 '''
   this function takes any webpage link and returns a report link from webhint.io.
'''
 u="https://webhint.io/scanner/"
 if proxy:
  proxy={'http':'http://'+proxy}
 r=''
 if ("://" not in ur):
  return r
 try:
  s=requests.session()
  s.get(u,proxies=proxy,timeout=timeout)
  data={"url":ur}
  a=s.post(u, data,proxies=proxy,timeout=timeout).text
  soup=BeautifulSoup(a, "html.parser")
  s=soup.find_all("span", class_="permalink-content")
  for x in s:
   try:
    r= x.a["href"]
   except Exception as ex:
    pass
 except Exception as e:
  pass
 return r
def youtube_search(q,proxy=None,timeout=10):
 '''
   this function is for searching on youtub and returning a links of related videos.
'''
 q=q.replace(" ","+")
 u="https://www.youtube.com/results"
 params={"search_query":q}
 l=[]
 try:
  r=requests.get(u,params,headers = {'User-Agent': random.choice(ua)},proxies=proxy,timeout=timeout).text
  soup=BeautifulSoup(r,"html.parser")
  yt = soup.find_all(attrs={'class':'yt-uix-tile-link'})
  for vi in yt:
   try:
    vi="https://www.youtube.com"+str(vi['href'])
    if (vi not in l):
     l.append(vi)
   except Exception as ex:
    pass
 except Exception as e:
  pass
 return l

def web_cams(count=10,by={'country':'us'},timeout=10):
 a=0
 f={}
 x=1
 if by:
  key=by.keys()[0].lower()
  if key not in ['country','tag','city','timezone','type']:
   raise Exception('Your search must be in one of these categories: country, city, timezone, type, tag')
  value=by[key].lower()
  url="https://www.insecam.org/en/by{}/{}/?page=".format(key,value)
 else:
  url="https://www.insecam.org/en/byrating/?page="
 while True:
  try:
   soup = BeautifulSoup(requests.get(url+str(x), headers={'User-Agent': random.choice(ua)},timeout=timeout).text,"html.parser")
   fi = soup.findAll('img',{'class':'thumbnail-item__img img-responsive'})
   for i in fi:
    j=HTMLParser.HTMLParser().unescape(i['src'])
    o=HTMLParser.HTMLParser().unescape(i['title'])
    f.update({j:o})
   if (len(fi)==0 ) or (a==len(f)):
    break
   a=len(f)
  except Exception as e:
   break
  if len(f)>=int(count):
    break
  x+=1
 return {k: f[k] for k in f.keys()[:int(count)]}