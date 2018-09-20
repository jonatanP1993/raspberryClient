import scapy.all as sca
import datetime
import signal
import threading
import requests
import subprocess
import time
import json
import requests
import argparse


ENDPOINT = 'https://heat-map-api.azure-api.net/CreateClientReadings'
GETURL = 'https://heat-map-api.azure-api.net/GenerateClientPositions'
HEADERS = {"Ocp-Apim-Subscription-Key":""}
MACURL = 'https://heat-map-api.azure-api.net/ReadAuthorizedMacAddresses'
VALIDMACS = []
def main():
    APID = "20"
    _INTERFACE = "wlan0mon"
    SEND_GET = False
    init()
    client = Listener(APID, _INTERFACE)
    
    if SEND_GET:
        tSendGet = threading.Thread(target=SendGet)
        tSendGet.daemon = True
        tSendGet.start()

    tGetMacs = threading.Thread(target=RetrieveMacs)
    tGetMacs.daemon = True
    tGetMacs.start()

    client.sniffTraffic()

def init():
    print("Starting airmon")
    resp = subprocess.call(["airmon-ng", "start", "wlan0"])
    if resp != 0:
        print("Could not start interface in monitor mode")
    print("Airmon-ng started")

def SendGet():
    while True:
        print("Sending GET request")
        r = requests.get(GETURL, headers=HEADERS)
        print("Get request response: " + str(r.status_code))
        time.sleep(30)

def RetrieveMacs():
    while True:
        print("Fetching MACS from Azure")
        response = requests.get(MACURL, headers=HEADERS)
        if response.status_code == 200:
            macs = response.json()
            print(macs)
            #IF VALID REPONSE  -> UPDATE THE LIST OF MACS
            print("List updated")
        time.sleep(120)


class Listener:
    def __init__(self, apid, interface):
        self.APID = apid
        self.interface = interface
        self.data = {}

    def sniffTraffic(self):
        try:

            while True:
                self.data = {}
                packets = sca.sniff(iface=self.interface, count=0, timeout=3)
                ts = datetime.datetime.now()
                for pkt in packets:
                    if pkt.addr2 not in VALIDMACS:
                        continue
                    temp = pkt.show(dump=True)
                    temp = temp.split("\n")
                    for k in temp:
                        if "dBm_AntSignal=" in k:
                            sig = self.format_signal(k)
                            self.addNewData(pkt.addr2, sig)
                
                self.send_data(ts, self.data)
                time.sleep(1)

        except KeyboardInterrupt:
            print("\nExiting program")
        finally:
            #Do cleanup
            print("Perform cleanup")

    def addNewData(self,mac, sig):
        if mac not in self.data:
            self.data[mac] = sig
        else:
            if self.data[mac] > sig:
                self.data[mac] = sig

    def build_json_helper(self, ts, mac, sig):
        test = {}
        test['AccessPointID'] = self.APID
        test['RSSI'] = sig.strip()
        test['MacAddress'] = mac
        test['TimeStamp'] = str(ts)
        
        return test 

    def build_json(self, ts, data):
        _json = []
        for x in data.keys() :
            mac = x
            sig = data[x]
            _json.append(self.build_json_helper(ts, mac, sig))
        jsonData = json.dumps(_json)
        return jsonData

    def send_data(self, ts, data):
        print('Sending data to API')    
        payload = self.build_json(ts, data)
        header = {'Content-Type':'application/json',
                'Ocp-Apim-Subscription-Key':''}
        response = requests.post(ENDPOINT, headers=header, data=payload)
        print(response.status_code)
        

    def format_signal(self, signalString):
        temp = signalString.split('=')
        if len(temp) > 1:
            return temp[1][:-3]
        return 100
    
    def toString(self):
        print("Raspberry client, APID = {}, Interface = {}".format(self.APID, self.interface))

if __name__ == "__main__":
    main()
