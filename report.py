import json
import sys
from datetime import datetime
import pandas as pd
import texttable as tt

def build_textual_row(index, data):
    all_fields = ['ipv4_addresses',
                  'ipv6_addresses',
                  'http_server',
                  'insecure_http',
                  'redirect_to_https',
                  'hsts',
                  'tls_versions',
                  'root_ca',
                  'rdns_names',
                  'rtt_range',
                  'geo_locations']
    textual_row = [index, datetime.utcfromtimestamp(data['scan_time'])]
    for field in all_fields:
        item = data[field]
        if isinstance(item, bool):
            textual_row.append('True' if item else 'False')
        elif isinstance(item, list):
            textual_row.append('\n'.join(map(str, item)))
        else:
            textual_row.append(item)
    return textual_row

def df_to_textual(data):
    # create text table
    tb = tt.Texttable()
    # add header and rows
    tb.set_cols_width([15,10,18,20,10,6,6,6,10,15,25,10,20])
    tb.set_cols_align(['c'] * 13)
    tb.header(["domain name", 
            "scan time",
            "ipv4 address",
            "ipv6 address",
            "http server",
            "http insecure",
            "redirect to https",
            "hsts",
            "tls versions",
            "root ca",
            "rdns names",
            "rtt range",
            "geo location"])
    for index, row in data.iterrows():
        tb.add_row(build_textual_row(index=index, data=row))
    return tb
    
def df_rtt_to_textual(data):
    # sort data first, by the minimum RTT (ordered from fastest to slowest)
    sorted_data = data.sort_values(by='rtt_range', key=lambda col: col.str[0])
    # create text table
    tb = tt.Texttable()
    # add header and rows
    tb.set_cols_align(['c'] * 3)
    tb.header(["domain name",
               "rtt minimum",
               "rtt maximum"])
    for index, row in sorted_data.iterrows():
        item = [index]
        item.append(row['rtt_range'][0])
        item.append(row['rtt_range'][1])
        tb.add_row(item)
    return tb

def df_ca_to_textual(data):
    # count number of occurrences for each observed root certificate authority
    occur_ca = data['root_ca'].value_counts()
    # create text table
    tb = tt.Texttable()
    # add header and rows
    tb.set_cols_align(['c'] * 2)
    tb.header(["root certificate authority",
               "number of occurrences"
               ])
    for i in range(occur_ca.size):
        item = [occur_ca.index[i], occur_ca[i]]
        tb.add_row(item)
    return tb

def df_server_to_textual(data):
    # count number of occurrences for each observed root certificate authority
    occur_server = data['http_server'].value_counts()
    # create text table
    tb = tt.Texttable()
    # add header and rows
    tb.set_cols_align(['c'] * 2)
    tb.header(["web server",
               "number of occurrences"
               ])
    for i in range(occur_server.size):
        item = [occur_server.index[i], occur_server[i]]
        tb.add_row(item)
    return tb
  
def df_support_to_textual(data):
    # count percentage of scanned domains supporting all statistics
    tmp_series = data['tls_versions'].str.contains('SSLv2', na=False, regex=False).value_counts()
    if True not in tmp_series:
        num_SSLv2 = 0
    else:
        num_SSLv2 = tmp_series[True]
    tmp_series = data['tls_versions'].str.contains('SSLv3', na=False, regex=False).value_counts()
    if True not in tmp_series:
        num_SSLv3 = 0
    else:
        num_SSLv3 = tmp_series[True]
    tmp_series = data['tls_versions'].str.contains('TLSv1.0', na=False, regex=False).value_counts()
    if True not in tmp_series:
        num_TLS10 = 0
    else:
        num_TLS10 = tmp_series[True]
    tmp_series = data['tls_versions'].str.contains('TLSv1.1', na=False, regex=False).value_counts()
    if True not in tmp_series:
        num_TLS11 = 0
    else:
        num_TLS11 = tmp_series[True]
    tmp_series = data['tls_versions'].str.contains('TLSv1.2', na=False, regex=False).value_counts()
    if True not in tmp_series:
        num_TLS12 = 0
    else:
        num_TLS12 = tmp_series[True]
    tmp_series = data['tls_versions'].str.contains('TLSv1.3', na=False, regex=False).value_counts()
    if True not in tmp_series:
        num_TLS13 = 0
    else:
        num_TLS13 = tmp_series[True]
    num_plain_http = len(data[data['insecure_http'] == True])
    num_https = len(data[data['redirect_to_https'] == True])
    num_hsts = len(data[data['hsts'] == True])
    num_ipv6 = len(data[data['ipv6_addresses'].str.len() != 0])

    # create text table
    tb = tt.Texttable()
    # add header and rows
    tb.set_cols_align(['c'] * 10)
    tb.header(["SSLv2",
               "SSLv3",
               "TLSv1.0",
               "TLSv1.1",
               "TLSv1.2",
               "TLSv1.3",
               "plain http",
               "https redirect",
               "hsts",
               "ipv6"
               ])
    item = [num_SSLv2, 
            num_SSLv3, 
            num_TLS10, 
            num_TLS11, 
            num_TLS12, 
            num_TLS13, 
            num_plain_http, 
            num_https, 
            num_hsts, 
            num_ipv6]
    item = [s / data.shape[0] for s in item]
    tb.add_row(item)
    return tb




def main(argv):
    # if len(argv) != 2:
    input_json_name = argv[1]
    output_text_name = argv[2]
    # opening json file
    with open(input_json_name) as f:
        data = json.load(f)
    # convert json file to pandas DataFrame
    df = pd.DataFrame(data).transpose()  

    # 1. a textual or tabular listing of all the information returned in Part 2.
    report_table1 = df_to_textual(df)
    # 2. a table showing the RTT ranges for all domains
    report_table2 = df_rtt_to_textual(df)
    # 3. a table showing the number of occurrences for each observed root certificate authority
    report_table3 = df_ca_to_textual(df)
    # 4. a table showing the number of occurrences of each web server 
    report_table4 = df_server_to_textual(df)
    # 5. a table showing the percentage of scanned domains supporting
    report_table5 = df_support_to_textual(df)

    # save to output txt
    # content = report_table1.draw() + '\n' + report_table2.draw() + '\n' + report_table3.draw() + '\n' + report_table4.draw() + '\n' + report_table5.draw()
    # with open(output_text_name, 'w') as f:
    #     f.write(content)
    with open(output_text_name, 'w') as f:
        f.write(report_table1.draw())
        f.write('\n')
        f.write(report_table2.draw())
        f.write('\n')        
        f.write(report_table3.draw())
        f.write('\n')
        f.write(report_table4.draw())
        f.write('\n')
        f.write(report_table5.draw())

if __name__ == '__main__':
    main(sys.argv)