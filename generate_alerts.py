#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 20 20:40:40 2023

@author: Smartsys
"""

import json
import random
from datetime import datetime, timedelta

# Constants
NUM_ALERTS = 1000
ALERT_TYPES = ['Unauthorized access', 'Login failure', 'File copied', 'Suspicious packet pattern']
SEVERITY_LEVELS = ['High', 'Medium', 'Low']

def generate_random_alerts(num_alerts=NUM_ALERTS):
    alerts = []
    for _ in range(num_alerts):
        alert_type = random.choice(ALERT_TYPES)
        severity = random.choice(SEVERITY_LEVELS)
        timestamp = datetime.now() - timedelta(days=random.randint(0, 30))
        alert = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'alert': alert_type,
            'severity': severity
        }
        alerts.append(alert)
    return alerts

def create_alert_file():
    alerts = generate_random_alerts()
    with open('alert.json', 'w') as file:
        json.dump(alerts, file, indent=4)

if __name__ == "__main__":
    create_alert_file()
