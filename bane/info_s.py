import requests,urllib,socket,random,time,re,threading,sys,whois,json,os,xtelnet
import bs4
from bs4 import BeautifulSoup
from bane.payloads import *
if  sys.version_info < (3,0):
    from scapy.config import conf
    conf.ipv6_enabled = False
    from scapy.all import *
else:
    from kamene.config import conf
    conf.ipv6_enabled = False
    from kamene.all import *
if os.path.isdir('/data/data/com.termux/')==False:
    import dns.resolver

def remove_html_tags(text):
    """Remove html tags from a string"""
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)


def get_banner(u,p=23,timeout=3,payload=None):
 try:
  return xtelnet.get_banner(u,p=p,timeout=timeout,payload=payload)
 except:
  return None


def info(u,timeout=10,proxy=None,logs=False,returning=True):
 '''
   this function fetchs all informations about the given ip or domain using check-host.net and returns them to the use as string
   with this format:
   'requested information: result'
    
   it takes 2 arguments:
   
   u: ip or domain
   timeout: (set by default to: 10) timeout flag for the request
   usage:
   >>>import bane
   >>>domain='www.google.com'
   >>>bane.info(domain)
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
  h=''
  u='https://check-host.net/ip-info?host='+u
  c=requests.get(u, headers = {'User-Agent': random.choice(ua)},proxies=proxy,timeout=timeout).text
  soup = BeautifulSoup(c,"html.parser")
  la=soup.find_all('a')
  l=[]
  for i in la:
   if "#ip_info-dbip" in str(i):
    l.append(remove_html_tags(str(i)).strip().replace('\n',' '))
   if "#ip_info-ip2location" in str(i):
    l.append(remove_html_tags(str(i)).strip().replace('\n',' '))
   if "#ip_info-geolite2" in str(i):
    l.append(remove_html_tags(str(i)).strip().replace('\n',' '))
  p=soup.find_all('table')
  o=0
  di={}
  for x in p:
   try:
    do={}
    y=x.find_all('tr')
    for w in y:
     a=w.find_all('td')
     try:
      c=str(a[0]).split('<td>')[1].split('</td>')[0].strip()
      d=str(a[1]).split('<td>')[1].split('</td>')[0].strip()
      d=remove_html_tags(d).strip().replace('\n',' ')
      do.update({c:d})
     except:
      pass
    di.update({l[o]:do})
    o+=1
   except:
    pass
  if logs==True:
   for x in di:
    print (x)
    print('')
    for y in di[x]:
     print(y+": "+di[x][y])
    print('')
  if returning==True:
   return di
 except:
  return None

def norton_rate(u,timeout=30,proxy=None):
 '''
   this function takes any giving and gives a security report from: safeweb.norton.com, if it is a: spam domain, contains a malware...
   it takes 3 arguments:
   u: the link to check
   logs: (set by default to: True) showing the process and the report, you can turn it off by setting it to:False
   returning: (set by default to: False) returning the report as a string format if it is set to: True.
   usage:
   >>>import bane
   >>>url='http://www.example.com'
   >>>bane.norton_rate(domain)
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
  ur=urllib.quote(u, safe='')
  ul='https://safeweb.norton.com/report/show?url='+ur
  c=requests.get(ul, headers = {'User-Agent': random.choice(ua)},proxies=proxy,timeout=timeout).text 
  soup = BeautifulSoup(c, "html.parser")
  s=soup.find_all('div', class_="communityRatings")
  s=remove_html_tags(str(s[0])).strip().split("\n")
  while("" in s) : 
    s.remove("") 
  try:
   return {"Profile":s[0],"Rate":float(s[1]),"By":s[2]}
  except:
   return {"Profile":s[0],"Rate":float(s[1])}
 except:
  pass

def myip(proxy=None,proxy_type=None,timeout=15):
 '''
   this function is for getting your ip using: ipinfo.io
   usage:
   >>>import bane
   >>>bane.myip()
   xxx.xx.xxx.xxx
'''
 proxies={}
 if proxy:
  if proxy_type.lower()=="http":
   proxies = {
     "http": "http://"+proxy,
     }
  if proxy_type.lower()=="socks4":
   proxies = {
     "http": "socks4://"+proxy,
      }
  if proxy_type.lower()=="socks5":
   proxies = {
     "http": "socks5://"+proxy,
      } 
 try:
   return requests.get("http://ipinfo.io/ip",headers = {'User-Agent': random.choice(ua)},  proxies=proxies ,timeout=timeout).text.strip()
 except:
  pass
 return ''

def who_is(u):
 u=u.replace('www.','')
 try:
  return whois.whois(u)
 except:
  pass
 return {}

def geoip(u,timeout=15,proxy=None):
 '''
   this function is for getting: geoip informations
 '''
 try:
   if proxy:
    proxy={'http':'http://'+proxy}
   r=requests.get('https://geoip-db.com/jsonp/'+u,headers = {'User-Agent': random.choice(ua)},proxies=proxy,timeout=timeout).text
   return json.loads(r.split('(')[1].split(')')[0])
 except:
  pass
 return {}


def headers(u,timeout=10,logs=True,returning=False,proxy=None):
 try:
   if proxy:
    proxy={'http':'http://'+proxy}
   s=requests.session()
   a=s.get(u,headers = {'User-Agent': random.choice(ua)} ,proxies=proxy,timeout=timeout).headers
 except Exception as ex:
   return None
 if logs==True:
  for x in a:
   print("{} : {}".format(x,a[x]))
 if returning==True:
  return a


def reverse_ip_lookup(u,timeout=10,logs=True,returning=False,proxy=None):
 '''
   this function is for: reverse ip look up
   if you've used it 100 times in 24 hours, your IP will be banned by "api.hackertarget.com" so i highly recommand you to use the "proxy" option by adding a http(s) proxy:

   bane.reverse_ip_lookup('XXX.XXX.XXX.XXX',proxy='IP:PORT')

 '''
 if proxy:
  proxy={'http':'http://'+proxy}
 try:
   r=requests.get("https://api.hackertarget.com/reverseiplookup/?q="+u,headers = {'User-Agent': random.choice(ua)} ,proxies=proxy,timeout=timeout).text
   return r.split('\n')
 except Exception as ex:
   pass
 return []
'''
   end of the information gathering functions using: api.hackertarget.com
'''


def resolve(u,server='8.8.8.8',timeout=1,lifetime=1):
 o=[]
 r = dns.resolver.Resolver()
 r.timeout = 1
 r.lifetime = 1
 r.nameservers = [server]
 a = r.query(u)
 for x in a:
  o.append(str(x))
 return o
"""
this class is used to scan a target for open ports

usage:

a=bane.port_scan("8.8.8.8",ports=[21,22,23,80,443,3306],timeout=5)
print(a.result)

this should give you a dict like this:

{'443': 'Open', '22': 'Closed', '21': 'Closed', '23': 'Closed', '80': 'Closed', '3306': 'Closed'}

"""

def get_local_ip():
 try:
  return [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
 except:
  return '127.0.0.1'

def host_alive(target):
 if os.name == 'nt':
  r = os.popen("ping -n 1 "+target).readlines() 
 else:
  r = os.popen("ping -c 1 "+target).readlines() 
 if "TTL" in str(r):
  r=None
  return True
 r=None
 return False


def tcp_scan(ip,port=1,timeout=2,retry=1,check_open=False):
    syn = IP(dst=ip) / TCP(dport=port, flags="S")
    ans, unans = sr(syn, timeout=timeout,retry=retry,verbose=0)
    for sent, received in ans:
        if check_open==True:
         if received[TCP].flags == "SA":
          return True
         else:
          return False
        if received[TCP].flags == "RA" or received[TCP].flags == "SA":
            return True
    return False


class port_scan:
 __slots__=["timeout","por","result","target","retry"]
 
 def scan (self):
        p=self.por[self.flag2]
        a= tcp_scan(self.target,port=int(p),check_open=True,timeout=self.timeout,retry=self.retry)
        if a==True:
         self.result.update({p:1})
        else:
         self.result.update({p:0})
         
 def __init__(self,u,ports=[21,22,23,25,43,53,80,443,2082,3306],timeout=2,retry=0):
  try:
   thr=[]
   self.retry=retry
   self.result={}
   self.timeout=timeout
   self.por=ports
   self.target=u
   for x in range(len(self.por)):
    self.flag2=x
    thr.append(threading.Thread(target=self.scan).start())
    time.sleep(.001)
   while(len(self.result)!=len(ports)):
    time.sleep(.1)
  except:
      pass
  for x in self.__dict__:
   if x!="result":
    self.__dict__[x]=None


class subdomains_finder:
 __slots__=["stop","finish","result"]
 def __init__(self,u,process_check_interval=5,logs=True,returning=False,requests_timeout=15,https=False):
  self.stop=False
  self.finish=False
  self.result=self.result={u:[]}
  t=threading.Thread(target=self.crack,args=(u,process_check_interval,logs,requests_timeout,https,))
  t.daemon=True
  t.start()
 def crack(self,u,process_check_interval,logs,requests_timeout,https):
  https_flag=0
  if (https==True) or('https://' in u):
     https_flag=1
  if "://" in u:
   host=u.split('://')[1].split('/')[0]
  else:
   host=u
  sd=[]
  while True:
   if self.stop==True:
    break
   try:
    s=requests.session()
    r=s.post('https://scan.penteston.com/scan_system.php',data={"scan_method":"S201","test_protocol":https_flag,"test_host":host},timeout=requests_timeout).text
    if '"isFinished":"no"' not in r:
     if logs==True:
      print("\n[+]Scan results:")
     c=r.split('strong><br\/>')[1].replace('"}','')
     for x in (c.split('<br\/>')):
      if logs==True:
       print(x)
       sd.append(x)
     break
    else:
     if logs==True:
      sys.stdout.write("\r[*]Scan in progress...")
      sys.stdout.flush()
     #print("[*]Scan in progress...")
   except KeyboardInterrupt:
      break
   except:
    pass
   try:
    time.sleep(process_check_interval)
   except KeyboardInterrupt:
       break
   except:
    pass
  self.finish=True
  self.result={u:sd}
 def done(self):
  return self.finish
  