import os 
import subprocess
import signal 

class TLS:
    def __init__(self,domain):
        self.domain = domain 
    
    def run_nmap(self):
        try:
            cmd = "nmap --script ssl-enum-ciphers -p 443 "+self.domain 
            return subprocess.check_output(cmd,
                timeout=10,stderr=subprocess.STDOUT,shell=True
            ).decode("utf-8")
        except Exception as x:
            print("error occurs running nmap",x)
            return ""
    
    def run_openssl(self):
        try:
            cmd = "echo | timeout 2 openssl s_client -timeout -connect "+self.domain+":443"
            return subprocess.check_output(cmd,input="",timeout=10,shell=True,stderr=subprocess.STDOUT)\
                .decode("utf-8")
        except Exception as x:
            print("error occurs running openssl",x)
            return ""
    
    def run(self):
        ##get nmap
        try:
            result = self.run_nmap()
        except Exception as x:
            result = ""
        
        collect = []
        for i in ["TLSv1.0","TLSv1.1","TLSv1.2"]:
            if i in result:
                collect.append(i)
        
        ##get openssl
        try:
            result = self.run_openssl()
        except Exception as x:
            result = ""
        
        if "New, TLSv1.3, Cipher" in result:
            collect.append("TLSv1.3")
        
        ca = "N/A" 
        #find root ca 
        if result != "":
            for line in result.splitlines():
                if "depth=" in line: 
                    #split by ,
                    args = line.split(",")
                    for arg in args:
                        if " O = " in arg:
                            ca = arg.split(" O = ")[1]
                            break 
        return collect,ca 