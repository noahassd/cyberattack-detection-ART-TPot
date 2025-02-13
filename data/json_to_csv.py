import json
import pandas as pd
import requests
from bs4 import BeautifulSoup
from typing import List, Dict
import geopandas
import numpy as np
from plotly import express as px
import warnings
import os

# Créer le dossier data_csv s'il n'existe pas
os.makedirs('data_csv', exist_ok=True)

# Honeytrap
def parse_honey_logs(logs: str) -> pd.DataFrame:
    json_logs = [json.loads(line) for line in logs.strip().split('\n')]
    flat_data = []
    for log in json_logs:
        flat_log = {
            'timestamp': log['timestamp'],
            'src_ip': log['src_ip'],
            'dst_port': log['dest_port'],
            'hostname': log['hostname'],
            'protocol': log['protocol'],
            'request_method': log['request_method'],
            'trapped': log['trapped'],
            'user_agent': log.get('user-agent', ''),
            'user_agent_browser': log.get('user-agent_browser', ''),
            'user_agent_browser_version': log.get('user-agent_browser_version', ''),
            'user_agent_os': log.get('user-agent_os', ''),
            'user_agent_os_version': log.get('user-agent_os_version', '')
        }
        headers = {
            k.replace('header_', ''): v 
            for k, v in log.items() 
            if k.startswith('header_')
        }
        for header_name, header_value in headers.items():
            flat_log[f'header_{header_name}'] = header_value
            
        flat_data.append(flat_log)

    df = pd.DataFrame(flat_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['trapped'] = df['trapped'].map({'true': True, 'false': False})
    return df

# Dionaea
def parse_dionaea_logs(logs: str) -> pd.DataFrame:
    json_logs = [json.loads(line) for line in logs.strip().split('\n')]
    flat_data = []
    for log in json_logs:
        flat_log = {
            'timestamp': log['timestamp'],
            'src_ip': log['src_ip'],
            'src_port': log['src_port'],
            'dst_ip': log['dst_ip'],
            'dst_port': log['dst_port'],
            'protocol': log['connection']['protocol'],
            'transport': log['connection']['transport'],
            'connection_type': log['connection']['type']
        }
        flat_data.append(flat_log)

    df = pd.DataFrame(flat_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

# Tanner
def parse_tanner_logs(logs: str) -> pd.DataFrame:
    json_logs = [json.loads(line) for line in logs.strip().split('\n')]
    flat_data = []
    for log in json_logs:
        flat_log = {
            'timestamp': log['timestamp'],
            'method': log['method'],
            'path': log['path'],
            'status': log['status'],
            'uuid': log['uuid'],
            'src_ip': log['peer']['ip'],
            'src_port': log['peer']['port'],
            'response_version': log['response_msg']['version'],
            'response_sess_uuid': log['response_msg']['response']['message']['sess_uuid'],
            'header_user-agent': log['headers']['user-agent']
        }
        flat_data.append(flat_log)

    df = pd.DataFrame(flat_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def create_ip_location_df(honeypot_dfs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    attributes_list = ['Honeypot', 'IP', 'Appearances', 'City', 'Zip Code', 'Region Code', 
                      'Region Name', 'Country Code', 'Country Name', 'Latitude', 'Longitude']
    ip_loc = pd.DataFrame(columns=attributes_list)
    
    for honeypot_name, df in honeypot_dfs.items():
        for ip in df['src_ip'].unique():
            ip_appearances = len(df[df['src_ip'] == ip])
            values_list = [honeypot_name, ip, ip_appearances]
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            r = requests.get(f"https://viewdns.info/iplocation/?ip={ip}", headers=headers)
            if r.status_code == 200:
                soup = BeautifulSoup(r.content, 'html.parser')
                s = soup.find('tbody', class_='bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700')
                values = s.find_all('td', class_='px-6 py-4 whitespace-nowrap text-base text-gray-500 dark:text-gray-400')
                for value in values:
                    values_list.append(value.text)
                ip_loc.loc[len(ip_loc)] = values_list
    
    return ip_loc

def main():
    # Charger et parser les données
    with open('data/h0neytr4p/log/log.json', 'r') as f:
        df_honeytrap = parse_honey_logs(f.read())
        
    with open('data/dionaea/log/dionaea.json', 'r') as f:
        df_dionaea = parse_dionaea_logs(f.read())
        
    with open('data/tanner/log/tanner_report.json', 'r') as f:
        df_tanner = parse_tanner_logs(f.read())
    
    # Sauvegarder les DataFrames en CSV
    df_honeytrap.to_csv('data_csv/honeytrap.csv', index=False)
    df_dionaea.to_csv('data_csv/dionaea.csv', index=False)
    df_tanner.to_csv('data_csv/tanner.csv', index=False)
    
    # Créer et sauvegarder le DataFrame des locations IP
    honeypot_dfs = {
        'honeytrap': df_honeytrap,
        'dionaea': df_dionaea,
        'tanner': df_tanner
    }
    
    ip_loc_df = create_ip_location_df(honeypot_dfs)
    ip_loc_df.to_csv('data_csv/ip_locations.csv', index=False)
    
    # Ajouter l'échelle pour la visualisation
    ip_loc_df['echelle'] = pd.cut(
        ip_loc_df['Appearances'],
        bins=[0, 5, 10, 50, 100, 500, 1000, 5000, float('inf')],
        labels=[1, 2, 3, 4, 5, 6, 7, 8],
        right=False
    )
    
    return ip_loc_df

if __name__ == "__main__":
    ip_loc_df = main()