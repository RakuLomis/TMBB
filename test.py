import os


pcap_directory = "wireshark_traffic\\test"
device = 'WLAN'
device_proxy = 'Meta'
# time = datetime.now().strftime("%y-%m-%d--%H-%M-%S")
# pcap_path_normal = 'Papers\\UserPattern\\wireshark_traffic\\test\\WLAN'
pcap_path_normal = os.path.join('.', pcap_directory, device)
pcap_path_proxy = os.path.join('..', pcap_directory, device_proxy)

# 检查目录是否存在
directory_path = pcap_path_normal

if os.path.exists(directory_path):
    print("目录存在")
else:
    print(f"目录不存在:{directory_path}")