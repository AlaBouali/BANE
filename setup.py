#for windows you need to download: winpcap: http://www.win10pcap.org/download/
import sys,setuptools,os,subprocess
with open("README.md", "r") as fh:
    long_description = fh.read()
termux=False
if os.path.isdir('/home/')==True:
 pm="apt"
 for x in ["apt","yum","pacman","dnf","zypper"]:
  if subprocess.call(["which", "apt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)==0:
   pm=x
   break
 os.system('sudo '+pm+' install sshpass -y')
 os.system('sudo '+pm+' install nodejs -y')
adr=False
if os.path.isdir('/data/data')==True:
    adr=True
if os.path.isdir('/data/data/com.termux/')==True:
    termux=True
    os.system('apt install openssh -y')
    os.system('pkg install sshpass -y')
    os.system('pkg install nodejs -y')
if termux==False:
   if  sys.version_info < (3,0):
    os.system('pip uninstall dnspython -y')
    os.system('pip install dnspython')
   else:
    os.system('pip3 uninstall dnspython -y')
    os.system('pip3 install dnspython')

#protobuf==3.6.1

if  sys.version_info < (3,0):
 req=["furl","future","xtelnet","requests","PySocks","bs4","mysqlcp","scapy","stem","cfscrape","python-whois","google","colorama","dnspython"]
 if adr==True:
    req=["furl","future","xtelnet","requests","PySocks","bs4","mysqlcp","cfscrape","scapy","python-whois","google","colorama","dnspython"]
 if termux==True:
    req=["furl","future","xtelnet","requests","PySocks","bs4","mysqlcp","scapy","cfscrape","python-whois","google","colorama","dnspython"]
else:
 req=["furl","future","xtelnet","requests","PySocks","bs4","mysqlcp","kamene","stem","cfscrape","python-whois","google","colorama","dnspython"]
 if adr==True:
    req=["furl","future","xtelnet","requests","PySocks","bs4","mysqlcp","cfscrape","kamene","python-whois","google","colorama","dnspython"]
 if termux==True:
    req=["furl","future","xtelnet","requests","PySocks","bs4","mysqlcp","kamene","cfscrape","python-whois","google","colorama","dnspython"]
if (sys.platform == "win32") or( sys.platform == "win64"):
 req+=["win_inet_pton"]


setuptools.setup(
    name="bane",
    version="4.4.7",
    author="AlaBouali",
    author_email="trap.leader.123@gmail.com",
    description="cyber security library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AlaBouali/bane",
    python_requires=">=2.7",
    install_requires=req,
    packages=["bane"],
    license="MIT License",
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License ",
    ],
)
