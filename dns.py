import subprocess 

class DNS:
    def __init__(self,ip_list):
        self.ip_list = ip_list 
    
    def run(self):
        rdns = []
        for ip in self.ip_list:
            result = self.run_ns(ip)
            if result!="":
                # print(result)
                for line in result.splitlines():
                    name = ""
                    if "name =" in line:
                        name = line.split("name =")[1].strip(" \t\r\n")
                    elif "Name:" in line:
                        name = line.split("Name:")[1].strip(" \t\r\n")
                    print("dns result:",name)
                    if name!=""and  name not in rdns:
                        rdns.append(name)
        return rdns 
    def run_ns(self,ip):
        try:
            return subprocess.check_output("nslookup "+ip,timeout=5,\
                stderr=subprocess.STDOUT,shell=True).decode("utf-8")
        except Exception as x:
            print("error running ns ",x)
            return ""