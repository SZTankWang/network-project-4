import subprocess 
import math 

class RTT:
    def __init__(self,ip_list):
        self.ip_list = ip_list

    
    def run_rtt(self,ip,port="443"):
        try:
            cmd = 'sh -c "time echo -e \'\\x1dclose\\x0d\' | timeout 5 telnet ' + ip + ' ' + port + '"'
            return subprocess.check_output(cmd, timeout=5,
                        stderr=subprocess.STDOUT, shell=True).decode("utf-8")

        except Exception as e:
            return None 

    def run(self,port="443"):
        min_v = float("inf") 
        max_v = float("-inf")

        for ip in self.ip_list:
            result = None 
            for port in ["443","80","22"]:
                result = self.run_rtt(ip=ip,port=port)
                if result is not None:
                    break 
            if result is not None and "real" in result:
                measured_time = result.split("real")[1].splitlines()[0].strip(" \t\r\n")
                try:
                    measured_time = float(measured_time[2:-1])
                    min_v = min(min_v,measured_time)
                    max_v = max(max_v,measured_time)
                except Exception as x:
                    print("error in converting measurement")
        
        if math.isinf(min_v) or math.isinf(max_v):
            return None 
        return [min_v,max_v]

