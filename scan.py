import json
import sys, os
import time
# add libraries
import subprocess
# import requests
from tls import TLS
from dns import DNS 
from rtt import RTT
from geo import GEO 

def scan_ip_address(domain, dns_list):
    ipv4 = []
    ipv6 = []
    for dns in dns_list:
        # scan ipv4 address
        # format of nslookup is 
        # Name:   google.com (domain)
        # Address: 216.58.212.46 (ip)
        try:
            result = subprocess.check_output(["nslookup", "-q=A", domain, dns],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            result_list = result.split('\n')
        except:
            result_list = []
        # patten = 'Name:\t%s'%(domain)
        patten = 'Name:\t'
        for i, j in enumerate(result_list):
            if patten in j:
                tmp_ip = result_list[i+1].split(": ")[1]
                if tmp_ip not in ipv4:
                    ipv4.append(tmp_ip)

        # scan ipv6 address
        # Name:   google.com (domain)
        # Address: 2607:f8b0:4009:80b::200e (ip)
        try:
            result = subprocess.check_output(["nslookup", "-q=AAAA", domain, dns],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            result_list = result.split('\n')
        except:
            result_list = []
        # for r in result_list:
        #     if "has AAAA address" in r:
        #         ipv6.append(r.split(" ")[-1])
        patten = 'Name:\t'
        for i, j in enumerate(result_list):
            if patten in j:
                tmp_ip = result_list[i+1].split(": ")[1]
                if tmp_ip not in ipv6:
                    ipv6.append(tmp_ip)

    return ipv4, ipv6


# def scan_http(ip):
#     server = None
#     insecure_flag = False
#     redirect_flag = False
#     hsts_flag = False
#     try:
#         # print("http://%s"%(ip))
#         r = requests.get("http://%s"%(ip), headers={"Content-Type":"application/json"})
#         # print(r.status_code)
#     except requests.exceptions.SSLError as error:
#         print("doesn't have SSL working properly (%s)" % (error, ))
#         return server, insecure_flag, redirect_flag, hsts_flag
#     # get http insecure flag
#     if r.status_code != 200:
#         insecure_flag = False
#     else:
#         insecure_flag = True
#     # get http server info
#     if 'Server' in r.headers:
#         server = r.headers['Server']
#     # get http redirect flag
#     redirect_list = r.history
#     if not redirect_list:
#         if len(redirect_list) > 10:
#             # give up if redirect more than 10 times
#             redirect_flag = False
#         else:
#             for redirect in redirect_list:
#                 url_next = redirect.headers['Location']
#                 r_next = requests.get(url_next, headers={"Content-Type":"application/json"})
#                 if r_next.status_code != 200:
#                     # give up if the website is broken
#                     redirect_flag = False
#                     break
#                 elif 'https' in url_next:
#                     # eventually reach an HTTPS page
#                     redirect_flag = True
#                     break
#     else:
#         # no redirection at all
#         redirect_flag = False 
#     # get http hsts flag
#     if 'strict-transport-security' in r.headers:
#         hsts_flag = True
#     return server, insecure_flag, redirect_flag, hsts_flag

def scan_http_curl(domain):
        server = None
        insecure = True
        redirect_to_https = False
        hsts = False
        try:
            result = subprocess.check_output(["curl", "-v", domain],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            result_list = result.split('\n')
        except:
            return server, insecure, redirect_to_https, hsts
        # check if http
        # matching = [s for s in result_list if "* connected to: " in s.lower()]
        # if not matching: # connection fails
        #     insecure = False
        # else:
        #     # check port number 80
        #     if "80" in matching[0]:
        #         insecure = True
        #     else:
        #         insecure = False
        # check server
        matching = [s for s in result_list if "< server: " in s.lower()]
        if not matching:
            server = None
        else:
            server = matching[0].split(": ")[1][:-1] # get server name
        # check hsts flag
        if any("< Strict-Transport-Security: " in s for s in result_list):
            hsts = True
        else:
            hsts = False
        # check redirect
        # firstly, check status code
        matching = [s for s in result_list if "< HTTP/" in s]
        status_code = int(matching[0].split(" ")[2])
        if status_code >= 300 and status_code < 310:
            # if redirection, check location
            num_of_redirect = 1
            matching = [s for s in result_list if "location: " in s.lower()]
            location = matching[0].split(": ")[1][:-1] # get redirection location
            # redirect 
            while num_of_redirect <= 10:
                if "https" in location:
                    # redirected to HTTPS requests
                    redirect_to_https = True
                    break
                else:
                    # keep tracking chain of several redirects
                    result = subprocess.check_output(["curl", "-v", location], 
                                                     timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    result_list = result.split('\n')
                    matching = [s for s in result_list if "< HTTP/" in s]
                    status_code = int(matching[0].split(" ")[2])
                    if status_code >= 300 and status_code < 310:
                        num_of_redirect += 1
                        matching = [s for s in result_list if "location: " in s.lower()]
                        location = matching[0].split(": ")[1][:-1] # get redirection location
                    else:
                        redirect_to_https = False
                        break
        else:
            redirect_to_https = False

        return server, insecure, redirect_to_https, hsts


def main(argv):
    # if len(argv) != 2:
    input_file_name = argv[1]
    output_file_name = argv[2]
    # parameters 
    domains = []        # list of domains to test
    scan_results = {}   # list of scan results
    dns_list = []       # list of DNS
    # read input files
    with open(input_file_name) as f:
        for line in f:
            domains.append(line.split('\n')[0])

    # read dns list
    if os.path.exists('./public_dns_resolvers.txt'):
        with open('./public_dns_resolvers.txt') as f:
            for line in f:
                dns_list.append(line.split('\n')[0])
    if not dns_list:
        dns_list = ['8.8.8.8']

    # scan each domain
    for domain in domains:
        contents = {}
        contents["scan_time"] = time.time()
        ipv4, ipv6 = scan_ip_address(domain, dns_list)
        contents["ipv4_addresses"] = ipv4
        contents["ipv6_addresses"] = ipv6
        server, insecure_flag, redirect_flag, hsts_flag = scan_http_curl(domain)
        contents['http_server'] = server
        contents['insecure_http'] = insecure_flag
        contents['redirect_to_https'] = redirect_flag
        contents['hsts'] = hsts_flag
        tls_collect,ca = TLS(domain=domain).run()
        contents["tls_versions"],contents["root_ca"] = tls_collect,ca 

        dns = DNS(ip_list=ipv4).run()
        contents["rdns_names"] = dns 

        rtt = RTT(ip_list=ipv4)
        contents["rtt_range"] = rtt.run()

        geo = GEO()
        contents["geo_locations"] = geo.run(ip_list=ipv4)
       
        # construct scan results dictionary
        scan_results[domain] = contents

    # save scan results to json file
    with open(output_file_name, "w") as f:
        json.dump(scan_results, f, sort_keys=True, indent=4)
    
if __name__ == '__main__':
    main(sys.argv)