""" This script should be launched before app starting, in order to catch the whole life circle of app.
We just pay attention to the creation of process and its ports, especailly the ports changes, e.g. the ports of Network Service process in chrome.exe.
"""

import psutil
import subprocess
import wmi
import argparse
import sys
import threading
import pythoncom
from datetime import datetime
import os 
from concurrent.futures import ThreadPoolExecutor

stop_monitoring = False
all_tcp_list, all_udp_list = [], []

def get_app_pids(name):
    pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == name:
            pids.append(proc.info['pid'])
    return pids

def get_ports_by_pid(pid):
    # ports = []
    udp_ports, tcp_ports = [], []
    try:
        # Run netstat command and filter by PID
        # In windows terminal, default encoder is 'cp850' or 'cp1252' instead of 'utf-8', 
        # which may lead to the ecoding fault if we use the default set 'utf-8'.
        result = subprocess.check_output(['netstat', '-ano'], text=True, encoding='cp1252')
        for line in result.splitlines(): # Handle the data in rows
            if str(pid) in line:
                parts = line.split()
                # if len(parts) >= 5:
                # if (parts[0] == 'TCP' or parts[0] == 'UDP'):
                #     local_address = parts[1]
                #     port = local_address.split(':')[-1]
                #     ports.append(port)
                if (parts[0] == 'UDP'):
                    local_address = parts[1]
                    udp_port = local_address.split(':')[-1]
                    udp_ports.append(udp_port)
                if (parts[0] == 'TCP'):
                    local_address = parts[1]
                    tcp_port = local_address.split(':')[-1]
                    tcp_ports.append(tcp_port)
    except Exception as e:
        print(f"Error getting ports for PID {pid}: {e}")
    # return ports
    return udp_ports, tcp_ports

def get_all_pid_ports(app_name='chrome.exe'):
    global all_tcp_list, all_udp_list
    app_pids = get_app_pids(app_name)
    for pid in app_pids:
        udp_ports, tcp_ports = get_ports_by_pid(pid)
        # print(f"PID: {pid}, UDP Ports: {udp_ports}, TCP Ports: {tcp_ports}")
        all_udp_list += [item for item in udp_ports if item not in all_udp_list]
        all_tcp_list += [item for item in tcp_ports if item not in all_tcp_list]


def on_process_creation(event, app_name='chrome.exe'): # event is a instance of Win32_Process
    # print(f"Event: {event}")
    # process = event.NewEvent
    process = event
    # print(f"Process: {process}")
    if process.Name == app_name:
        pid = process.ProcessId
        print(f"New chrome.exe process detected: PID {pid}") 
        udp_ports, tcp_ports = get_ports_by_pid(pid)
        all_udp_list.extend([port for port in udp_ports if port not in all_udp_list])
        all_tcp_list.extend([port for port in tcp_ports if port not in all_tcp_list])
        # ports = get_ports_by_pid(pid)
        # print(f"PID: {pid}, Ports: {ports}")
        # print("----------------------------")
        # get_all_pid_ports()

def on_process_termination(event, app_name='chrome.exe'): # Don't care
    # process = event.NewEvent
    process = event
    if process.Name == app_name:
        pid = process.ProcessId
        print(f"chrome.exe process terminated: PID {pid}")

def monitor_app_ports(app_name='chrome.exe', time_out=1000):
    global stop_monitoring
    pythoncom.CoInitialize() # for threading
    try: 
        c = wmi.WMI()
        process_creation_watcher = c.Win32_Process.watch_for("creation")
        process_termination_watcher = c.Win32_Process.watch_for("deletion")

        with ThreadPoolExecutor(max_workers=4) as executor: 
            while not stop_monitoring: # time_out is the time limitaion of one circle
                try:
                # creation_event = process_creation_watcher(time_out) # timeout_ms is the max waiting time
                # if creation_event:
                #     on_process_creation(creation_event, app_name)

                    creation_events = []
                    print("events[] starts. Press 'Q' to exit.")
                    while not stop_monitoring:
                        try:
                            creation_event = process_creation_watcher(time_out)
                            if creation_event: # the creation activity is captured.
                                get_all_pid_ports()
                                creation_events.append(creation_event)
                                # print(creation_events)
                        except wmi.x_wmi_timed_out:
                            print("One circle timeout.")
                            break

                    for event in creation_events:
                        executor.submit(on_process_creation, event, app_name) 

                # termination_event = process_termination_watcher(time_out)
                # if termination_event:
                #     on_process_termination(termination_event, app_name)

            # except wmi.x_wmi_timed_out:
            #     # Timeout occurred, continue to next iteration
            #     continue
                except Exception as e:
                    print(f"Error: {e}")
        
    finally:
        pythoncom.CoUninitialize()

def listen_for_quit():
    global stop_monitoring
    while True:
        user_input = input()
        if user_input.strip().upper() == 'Q':
            stop_monitoring = True
            break

def to_wireshark_filter(udp_ports, tcp_ports):
    udp_filter = f"udp.port in {{{', '.join(udp_ports)}}}"
    tcp_filter = f"tcp.port in {{{', '.join(tcp_ports)}}}"
    combined_filter = f"({udp_filter}) or ({tcp_filter})"
    current_time = datetime.now().strftime("%y-%m-%d--%H-%M-%S")
    file_name = f"Papers\\UserPattern\\wireshark_order\\{current_time}.txt"

    with open(file_name, 'w') as file:
        file.write(combined_filter)

if __name__ == "__main__":
    # Set the entrance parameter of script
    parser = argparse.ArgumentParser(description="Monitor process ports")
    parser.add_argument("--process", type=str, default="chrome.exe", help="Name of the application to monitor")
    parser.add_argument("--timeout", type=int, default=5000, help="Timeout in milliseconds for event watcher")

    args = parser.parse_args()

    monitor_thread = threading.Thread(target=monitor_app_ports, args=(args.process, args.timeout))
    monitor_thread.start()

    input_thread = threading.Thread(target=listen_for_quit)
    input_thread.start()

    monitor_thread.join()
    print("Monitoring stopped. Generating wireshark filter.")

    all_udp_ports_set = set(all_udp_list)
    all_tcp_ports_set = set(all_tcp_list)
    print('udp ports: ', all_udp_ports_set)
    print('tcp ports: ', all_tcp_ports_set)
    to_wireshark_filter(all_udp_ports_set, all_tcp_ports_set)
    print('Wireshark order has been generated.')
    # monitor_app_ports(args.process, args.timeout)


