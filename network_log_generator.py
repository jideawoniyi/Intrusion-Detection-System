#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 20 21:10:39 2023

@author: Smartsys
"""

import random
from datetime import datetime, timedelta

# Constants
NUM_ENTRIES = 1000
IP_ADDRESSES = ['192.168.1.' + str(i) for i in range(1, 11)]
EVENTS = [
    "Login success from {}",
    "Login failure from {} - Incorrect password",
    "File copied from /home/user/docs to /home/user/backup by {}",
    "Folder accessed: /var/www/html by {}",
    "Packet transmission from {} to 10.0.0.15: 300 packets",
    "Unauthorized file access attempt in /etc/passwd from {}",
    "Data request from {} to server",
    "Connection terminated unexpectedly from {}",
    "Suspicious packet pattern detected from {}",
    "Login success from {}",
    "File deletion: /home/user/temp.txt by {}",
    "Connection established from {}",
    "High volume of traffic from {} to external server",
    "Login failure from {} - User not recognized",
    "Data transfer from {} to 10.0.0.15",
    "System alert: Potential DDoS attack from {}",
    "Network configuration changed by {}",
    "External device connected from {}"
]

def generate_log_entry():
    event = random.choice(EVENTS)
    ip = random.choice(IP_ADDRESSES)
    time_stamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
    return time_stamp.strftime('%Y-%m-%d %H:%M:%S') + ' ' + event.format(ip)

def create_network_log():
    with open('network.log', 'w') as file:
        for _ in range(NUM_ENTRIES):
            file.write(generate_log_entry() + '\n')

if __name__ == "__main__":
    create_network_log()
