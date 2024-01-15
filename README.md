This script leverages ICMP Echo Request and ICMP Echo Reply to test the functionality of FortiSIEM configuration to trigger events like SSH Brute Force attack, Network Scan, /etc/hosts integrity check and Computer Worm.
1. It scans the local network for ICMP Replies.
2. It scans the local network for active TCP sockets.
3. Simulates successful SSH brute-force and logs into the server.
4. Copies itself to the bruted host.
