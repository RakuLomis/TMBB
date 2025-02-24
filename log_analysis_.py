import pandas as pd
import re
import os
from datetime import datetime
from dateutil import parser

def convert_timestamps(timestamp): 
    """ Split the timestamp and change it into the form of clash log. 

    The shape of timestamp extracted from file name is like
    '24-09-26--17-03-48--20-04-24'. 
    It will be changed into two timestamps like 
    '2024-09-26T17:03:48.0000000+08:00' and
    '2024-09-26T20:04:24.0000000+08:00'. 
    """
    # Split
    parts = timestamp.split('--') 
    
    dt1 = datetime.strptime(parts[0] + '--' + parts[1], '%y-%m-%d--%H-%M-%S') 
    dt2 = datetime.strptime(parts[0] + '--' + parts[2], '%y-%m-%d--%H-%M-%S') 
    
    formatted_timestamp1 = dt1.strftime('20%y-%m-%dT%H:%M:%S.0000000+08:00') 
    formatted_timestamp2 = dt2.strftime('20%y-%m-%dT%H:%M:%S.0000000+08:00') 
    
    return formatted_timestamp1, formatted_timestamp2 

def logCutoff(pre_timestamp, input_log, output_log): 
    """ Cutoff the content of input_log in time duration [pre_timestamp, ), 
    and write the result into output_log. 

    *We don't use post_timestamp because the proxy may not be closed after collecting data. 
    We add the post_timestamp again because we need to guaratee the ports from chrome. 

    timestamp is like '2024-09-23T16:39:49.4519276+08:00'. 
    """
    cutoff_time_pre = parser.isoparse(pre_timestamp)
    # cutoff_time_post = parser.isoparse(post_timestamp)

    # open log file
    with open(input_log, 'r', encoding='utf-8') as file, open(output_log, 'w', encoding='utf-8') as new_file:
        for line in file:
            # extract timestamp of each line
            time_str = line.split(' ')[0].split('=')[1].strip('"')
            log_time = parser.isoparse(time_str)
        
            # examine whether the lines are in time duration
            if log_time >= cutoff_time_pre: 
                new_file.write(line)

def logToDataframe(input_log): 
    """ Turn 'time' and 'msg' in log to dataframe, which will be handled with list 
    firstly. 

    log_data = [{'time': '2024-09-23T16:39:49.4519276+08:00', 'msg': 'xxx'}]
    """
    pattern = r'time="([^"]+)" level=[^ ]+ msg="([^"]+)"'

    log_data = []
    with open(input_log, 'r', encoding='utf-8') as file: 
        for line in file: 
            match = re.search(pattern, line) 
            if match: 
                log_entry = {
                    'time': match.group(1), 
                    'msg': match.group(2) 
                }
                log_data.append(log_entry)
    df = pd.DataFrame(log_data, columns=['time', 'msg'])
    return df

def getConnInfo(log_df: pd.DataFrame): 
    """ Filter out all the connection information entries from log_df, 

    return  list_connection = [inLoc: 142.251.170.139:443, inRemote: 198.18.0.1:62080, outLoc: 192.168.5.2:62086, outRemote: 221.5.100.174:2064]
    """
    pattern_conn = r'^inLoc' 
    list_connection = [] 
    for i in range(log_df.shape[0]): 
        if re.match(pattern_conn, log_df['msg'].iloc[i]): 
            list_connection.append(log_df['msg'].iloc[i])
    return list_connection

def connDataFrame(list_connection: list): 
    inRemoteIP, inRemotePort = [], []
    inLocIP, inLocPort = [], []
    outLocIP, outLocPort = [], []
    outRemoteIP, outRemotePort= [], []
    pattern_conninfo = r'(\d+\.\d+\.\d+\.\d+):(\d+)'

    for entry in list_connection: 
        matches = re.findall(pattern_conninfo, entry) 
        # print()
        inRemoteIP.append(matches[1][0]), inRemotePort.append(matches[1][1])
        inLocIP.append(matches[0][0]), inLocPort.append(matches[0][1]) 
        outLocIP.append(matches[2][0]), outLocPort.append(matches[2][1])
        outRemoteIP.append(matches[3][0]), outRemotePort.append(matches[3][1])
    
    df_connection = pd.DataFrame({
    'inRemoteIP': inRemoteIP,
    'inRemotePort': inRemotePort,
    'inLocIP': inLocIP,
    'inLocPort': inLocPort,
    'outLocIP': outLocIP,
    'outLocPort': outLocPort,
    'outRemoteIP': outRemoteIP,
    'outRemotePort': outRemotePort
    })

    return df_connection

def processPortFilter(process_port_path, df_connection: pd.DataFrame): 
    pattern_process = r'tcp\.port in \{([0-9, ]+)\}' 
    with open(process_port_path, 'r') as file: 
        for line in file: 
            tcp_ports = re.search(pattern_process, line) 
            if tcp_ports: 
                process_port_tcp = [str(port.strip()) for port in tcp_ports.group(1).split(',')] 
    df_conn_filter = df_connection[df_connection['inRemotePort'].isin(process_port_tcp)]
    return df_conn_filter

def logAnalysis(pre_timestamp, input_log, output_log, process_port_path): 
    """ The pipeline of log cutoff and dataframe transform. 

    Returns:
        pd.DataFrame: IP and port of inbound and outbound, including inRemote, 
        inLoc, outLoc, outRemote (each have IP and port). 
    """
    logCutoff(pre_timestamp, input_log, output_log)
    log_df = logToDataframe(output_log)
    list_conn = getConnInfo(log_df)
    df_conn = connDataFrame(list_conn)
    df_conn_filter = processPortFilter(process_port_path, df_conn)
    return df_conn_filter

def outboundPort(df_conn_filter): 
    outboundPorts = set(df_conn_filter['outLocPort'])
    tcp_filter = f"tcp.port in {{{', '.join(outboundPorts)}}}" 
    return tcp_filter

if __name__ == "__main__": 
    log_file_path = os.path.join('Papers', 'UserPattern', 'wireshark_traffic', 'tshark', 'log', '2024-09-26-1444.log')
    output_log_path = os.path.join('Papers', 'UserPattern', 'wireshark_traffic', 'tshark', 'output_log', 'cutoff-2024-09-26-1444.log')
    process_port_path = os.path.join('Papers', 'UserPattern', 'wireshark_order', '24-09-26--17-03-48.txt')
    pre_time_stamp = "2024-09-23T16:43:39.5558452+08:00"
    connection_path = os.path.join('Papers', 'UserPattern', 'wireshark_traffic', 'tshark', 'conn', '24-09-26--17-03-48.csv')

    df_conn_filter = logAnalysis(pre_time_stamp, log_file_path, output_log_path, process_port_path)
    df_conn_filter.to_csv(connection_path, index=False, encoding='utf-8')
    print(outboundPort(df_conn_filter))