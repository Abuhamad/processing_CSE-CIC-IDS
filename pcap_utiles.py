import numpy as np
import pandas as pd
import os
import glob
import csv

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp
import binascii
from datetime import datetime
import pytz

pcap_data_path = '/media/mo/HDD/intrusion_detection/dataset/OriginalNetwork TrafficandLogdata/'
csv_data_path = '/media/mo/HDD/intrusion_detection/dataset/ProcessedTrafficDataforMLAlgorithms/'
csv_dist_path = '/media/mo/HDD/intrusion_detection/dataset/AttacksRecords/'

#Processed Traffic Data
files = ['Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv',
        'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv',
        'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv',
        'Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv',
        'Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv',
        'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv',
        'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv',
        'Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv',
        'Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv',
        'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv']


def read_file (file_):
    #input the name for the CSV file
    file_ = csv_data_path+file_
    with open(file_, 'r') as f:
        contents = [x.split(',') for x in f.readlines()]
        f.flush()
    return contents

def day_attack(file_):
    #input the content of csv file as np array
    return [item for item in np.unique(file_[:,-1]) if item!='Benign\n' and item!='Label\n']

def file_features(file_):
    #input the content of csv file as np array
    return file_[0]

def extract_flowdata(file_, attack_names):
    #input the content of csv file as np array
    dstPort=[]
    protocol=[]
    #attack_records = [file_[0].tolist()]
    attack_records = [file_[0]]
    for name in attack_names:
        #record=[item.tolist() for item in file_ if item[-1]==name]
        record=[item for item in file_ if item[-1]==name]
        attack_records.extend(record)
        dstPort.append(np.unique(np.array(record)[:,0]).tolist())
        protocol.append(np.unique(np.array(record)[:,1]).tolist())
    return np.array(attack_records), dstPort, protocol

def write_to_file(file_, name):
    #input attack records
    df = pd.DataFrame(data=file_[1:], columns=file_[0])
    df.to_csv(csv_dist_path+name, index=False)
    return df
    
def normalized_timestamp(ts):
    return(str(datetime.utcfromtimestamp(ts)))


def convert_datetime_timezone(dt, tz1, tz2):
    tz1 = pytz.timezone(tz1)
    tz2 = pytz.timezone(tz2)
    dt = datetime.strptime(dt,"%Y-%m-%d %H:%M:%S")
    dt = tz1.localize(dt)
    dt = dt.astimezone(tz2)
    dt = dt.strftime("%Y-%m-%d %H:%M:%S")
    return dt

def get_all_flows(capdata):
    #input capdata
    flows =[]
    timestamps=[]
    for pkt in capdata.packets:
        eth_frame = ethernet.Ethernet(pkt.raw())
        try:
            ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
            tcp_packet = tcp.TCP(binascii.unhexlify(eth_frame.payload))
        except:
            continue
        flows.append([ip_packet.src.decode("utf-8"), ip_packet.dst.decode("utf-8"), str(tcp_packet.src_port), str(tcp_packet.dst_port), str(ip_packet.p)])
        timestamps.append(normalized_timestamp(pkt.timestamp))
    return np.unique(flows, axis=0), flows,timestamps


def get_attack_flows(flows, attacker_ip):
    #input unique_flows
    if attacker_ip in np.unique(flows[:,0]):
        attacker_fwd_flows=[item.tolist() for item in flows if item[0]==attacker_ip]
    else:
        attacker_fwd_flows=[]
        print('Attacker IP does not exist !!!')
        
    if attacker_ip in np.unique(flows[:,1]):
        attacker_bwd_flows=[item.tolist() for item in flows if item[1]==attacker_ip]
    else:
        attacker_bwd_flows=[]
        print('Attacker IP does not exist !!!')
    
    return attacker_fwd_flows, attacker_bwd_flows   


def write_labels(attacker_fwd_flows, attacker_bwd_flows, attack):
    uni_labeled_file = open(csv_dist_path+"uni_labels.txt", 'a')
    for item in attacker_fwd_flows:
        for initem in item:
            uni_labeled_file.write(initem +',')
        uni_labeled_file.write(attack)

    bi_labeled_file = open(csv_dist_path+"bi_labels.txt", 'a')
    for item in attacker_fwd_flows:
        for initem in item:
            bi_labeled_file.write(initem +',')
        bi_labeled_file.write(attack)
    for item in attacker_bwd_flows:
        for initem in item:
            bi_labeled_file.write(initem +',')
        bi_labeled_file.write(attack)
    uni_labeled_file.close()
    bi_labeled_file.close()
    
def attack_active_time(attacker_fwd_flows,flows,timestamps):
    for item in attacker_fwd_flows:
        i = []
        j = 0
        for idx, itemx in enumerate(flows):
            if item==itemx:
                i.append(idx)
                j+=1

        begin_time=convert_datetime_timezone(timestamps[i[0]], "UTC", "Canada/Atlantic")
        end_time=convert_datetime_timezone(timestamps[i[-1]], "UTC", "Canada/Atlantic")
        print("Flow: {}\n\nBegin: {}   End: {}\n\nNumber of packets: {}\n" .format(item, begin_time,end_time,j))

        
def get_all_flows_2(cap, attackers, write_to_file):
    #input file object and a file to write the flows in formation 
    flow_file = open (write_to_file,'a') 
    flows =[]
    timestamps=[]
    for pkt in savefile.load_savefile(cap, lazy=True).packets:
        eth_frame = ethernet.Ethernet(pkt.raw())
        try:
            ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
            tcp_packet = tcp.TCP(binascii.unhexlify(eth_frame.payload))
        except:
            continue
        if ip_packet.src.decode("utf-8") in attackers:
            flow_file.write('{},{},{},{},{},{}\n'.format(ip_packet.src.decode("utf-8"), ip_packet.dst.decode("utf-8"), str(tcp_packet.src_port), str(tcp_packet.dst_port), str(ip_packet.p),normalized_timestamp(pkt.timestamp)))
        else:
            continue
    flow_file.close()
    
def read_unique_flows(file_):
    #file_ =csv_dist_path+file_
    with open (file_,'r') as f:
        contents = f.readlines()
        f.flush()
    return list(set(contents))



def get_attacks_labels(unique_flows, attack_time, attack_name,labels_file): 
    flows = [item.split(',') for item in unique_flows]
    #time = [item.split()[-1] for item in np.array(flows)[:,-1]]
    attack_flow = open(labels_file,'a')
    for item in flows:
        time = item[-1].split()[-1]
        if time > attack_time[0] and time < attack_time[1]:
            attack_flow.write('{},{},{},{},{},{}\n'.format(item[0],item[1],item[2],item[3],item[4],attack_name))
    attack_flow.close()   

