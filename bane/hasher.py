import hashlib,base64,sys

def xor_hash(data, key):
 '''
   function to return XOR encrypted string
 '''
 i=0
 c=""
 l=len(data)
 k=len(key)
 if (not data) or (l==0):
     raise Exception("You must provide data")
 if (not key) or (k==0):
     raise Exception("You must provide a key")
 while (i<l):
   for x in key:
     if i==l:
       break
     if type(data[i])==str:
      c+=chr(ord(data[i])^ord(x))
     else:
      c+=chr(data[i]^ord(x))
     i+=1
 i=None
 l=None
 k=None
 data=None
 key=None
 return c
def md5_hash(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return md5 encrypted string
  '''
  return hashlib.md5(w).hexdigest()
def sha1_hash(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return sha1 encrypted string
  '''
  return hashlib.sha1(w).hexdigest()
def sha256_hash(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return sha256 encrypted string
  '''
  return hashlib.sha256(w).hexdigest()
def base64_encode(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return base64 encoded string
  '''
  return base64.b64encode(w)
def base64_decode(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return base64 decoded string
  '''
  return base64.b64decode(w)
def sha224_hash(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return sha224 encrypted string
  '''
  return hashlib.sha224(w).hexdigest()
def sha384_hash(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return sha384 encrypted string
  '''
  return hashlib.sha384(w).hexdigest()
def sha512_hash(w,encode=None):
 if w:
  if encode:
   w.encode(encode)
  '''
   function to return sha512 encrypted string
  '''
  return hashlib.sha512(w).hexdigest()
'''
  the following functions are taking a file path and return encrypted content of  the file with the defined encryption method in the function's
  name.

  usage:

  >>>import bane
  >>>bane.md5fl('ala.txt')
  '66eab7dfd5c98ca5fbbbda6f7d7b36c3'
'''
def xor_file(f,key):
 if f and key:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return xor(w,key)
def md5_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return md5_hash(w)
def sha1_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return sha1_hash(w)
def sha224_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return sha224_hash(w)
def sha256_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return sha256_hash(w)
def sha384_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return sha384_hash(w)
def sha512_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return sha512_hash(w)
def base64_encode_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return base64_encode(w)
def base64_decode_file(f):
 if f:
  with open(f,"rb") as f: 
   w=f.read()
  f.close()
  return base64_decode(w)
'''
  the following functions are recommanded to be used in bruteforce attacks to crack the hashed passwords.

  they take 2 arguments:

  the first one is a word to encrypt it and compare it to the second argument that takes the hash that you are trying to crack.

  if it returns:
  False => the hashes didn't match
  True => the hashes has matched

  example:

  >>>hash='e88e6128e26eeff4daf1f5db07372784'
  >>>l=['admin','12345','user','ala','soul','vince']
  >>>fox word in l:
  ... print'[*]Trying:',word
      if bane.dmd5( word,hash)==True:
       print'[+]Found!!'
       break
      else:
       print'[-]failed'
'''
def dsha224(w,z):
 if w and z:
  w=hashlib.sha224(w).hexdigest()
  if w==z:
   return True
  return False
def dsha384(w,z):
 if w and z:
  w=hashlib.sha384(w).hexdigest()
  if w==z:
   return True
  return False
def dsha512(w,z):
 if w and z:
  w=hashlib.sha512(w).hexdigest()
  if w==z:
   return True
  return False
def dsha256(w,z):
 if w and z:
  w=hashlib.sha256(w).hexdigest()
  if w==z:
   return True
  return False
def dsha1(w,z):
 if w and z:
  w=hashlib.sha1(w).hexdigest()
  if w==z:
   return True
  return False
def dmd5(w,z):
 if w and z:
  w=hashlib.md5(w).hexdigest()
  if w==z:
   return True
  return False
'''
  function to do simple caesar encryption lol.
  
  it takes 2 arguments:

  the first one is the string to encrypt and the second is the second is the encryption key (integer between: 1 and 26)

  example:

  >>> bane.caesar('ala',5)
  'fqf'
'''
def caesar_hash(w,k):
 if (type(k) is not int) or (k not in range(1,27)):
     raise Exception('the key must be an integer between: 1 and 26')
 if (not w) or (len(w)==0):
     raise Exception("You must provide data")
 a='abcdefghijklmnopqrstuvwxyz'
 b='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
 c=''
 for i in w:
  """if (k>26) or (k<1) or (ord(i) not in range(32,127)):
   break"""
  if (i in a):
   c+=a[(a.index(i)+k)%26]
  elif i in b:
   c+=b[(b.index(i)+k)%26]
  else:
    c+=i
 return c
'''
  function to do simple caesar decryption lol.
  
  it takes 2 arguments:

  the first one is the string to decrypt and the second is the second is the decryption key (integer between: 1 and 26)

  example:

  >>> bane.dcaesar('fqf',5)
  'ala'
'''
def dcaesar(w,k):
 if (type(k) is not int) or (k not in range(1,27)):
     raise Exception('the key must be an integer between: 1 and 26')
 if (not w) or (len(w)==0):
     raise Exception("You must provide data")
 a='abcdefghijklmnopqrstuvwxyz'
 b='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
 c=''
 for i in w:
  """if (k>26) or (k<1) or (ord(i) not in range(32,128)):
   break"""
  if (i in a):
   c+=a[(a.index(i)-k)%26]
  elif i in b:
   c+=b[(b.index(i)-k)%26]
  else:
    c+=i
 return c
