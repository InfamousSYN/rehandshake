#!/usr/bin/python3
from scapy.all import *
import sys
import binascii

def optionsFunc():
    import argparse
    __version__ = '1.0'

    parser = argparse.ArgumentParser(description='Automated tool for repairing broken 4-way handshakes')

    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument('--verbose', '-v', action='count', dest='verbosity', default=0)
    parser.add_argument('--file', '-f', dest='in_file', type=str, help='specify pcap file containing the handshake')
    parser.add_argument('--output-file', '-o', dest='out_file', type=str, help='specify name for repaired pcap file')

    targetInformationOptions = parser.add_argument_group(description='Controls for specifying target SSID')
    targetInformationOptions.add_argument('--SSID', '-s', dest='SSID', type=str, help='specify target SSID')

    repairOptions = parser.add_argument_group(description='Specify repair techniques')
    repairOptions.add_argument('--all', '-a', dest='PerformTechniqueAll', action='store_true', help='perform all repair techniques')
    repairOptions.add_argument('-1', dest='enableTechnique1', action='store_true', help='Check for EAPOL Message 1 with PMKID and adds missing Beacon frame')
    repairOptions.add_argument('-2', dest='enableTechnique2', action='store_true', help='Check for EAPOL Message 1 + Message 2 sequence and adds missing Beacon frame')
    repairOptions.add_argument('-3', dest='enableTechnique3', action='store_true', help='Check for EAPOL Message 2 + Message 3 sequence and adds missing Beacon & EAPOL Message 1 frames')

    args, leftover = parser.parse_known_args()
    options = args.__dict__

    return options

class repairHandshake(object):

    @classmethod
    def __init__(self, packets_filename=None, ssid=None, PerformTechniqueAll=False, PerformTechniqueCandidate1=False, PerformTechniqueCandidate2=False, PerformTechniqueCandidate3=False):
        self.packets_filename=packets_filename
        self.ssid=ssid
        self.candiate1Status=False
        self.craftEapol1FrameList = []
        self.PerformTechniqueCandidate1=PerformTechniqueCandidate1
        self.PerformTechniqueCandidate2=PerformTechniqueCandidate2
        self.PerformTechniqueCandidate3=PerformTechniqueCandidate3
        self.PerformTechniqueAll=PerformTechniqueAll

        if(self.PerformTechniqueAll):
            self.PerformTechniqueCandidate1=True
            self.PerformTechniqueCandidate2=True
            self.PerformTechniqueCandidate3=True

    @classmethod
    def extractFrames(self):
        try:
            self.packets_eapol = []
            self.packets_beacon = []
            self.knownBeaconBSSID = []
            self.eapol_message1_list = []
            self.eapol_message2_list = []
            self.eapol_message3_list = []
            self.eapol_message4_list = []
            self.eapol_message1_pmkid = []
            self.eapol_message1_pmkid_bssid = []

            eapolKnownState = []
            beaconKnownState = []
            for pkt in self.in_file_pcap:
                if(pkt.haslayer(EAPOL)):
                    self.packets_eapol.append(pkt)
                    if(pkt.getlayer(Dot11).addr3 not in eapolKnownState):
                        eapolKnownState.append(pkt.getlayer(Dot11).addr3)

            for pkt in self.in_file_pcap:
                if((pkt.haslayer(Dot11Beacon)) and (pkt.getlayer(Dot11).addr3 in eapolKnownState) and (pkt.getlayer(Dot11).addr3 not in beaconKnownState)):
                        self.packets_beacon.append(pkt)
                        beaconKnownState.append(pkt.getlayer(Dot11).addr3)
            print('[-]   Number of Beacon frames found: {}'.format(len(self.packets_beacon)))
            print('[-]   Number of EAPOL frames found: {}'.format(len(self.packets_eapol)))

            for index in range(len(self.packets_eapol)):
                if(bytes(self.packets_eapol[index].getlayer(Raw).load)[1:3] == b'\x00\x8a'):
                    self.eapol_message1_list.append(self.packets_eapol[index])
                if(bytes(self.packets_eapol[index].getlayer(Raw).load)[1:3] == b'\x01\x0a'):
                    self.eapol_message2_list.append(self.packets_eapol[index])
                if(bytes(self.packets_eapol[index].getlayer(Raw).load)[1:3] == b'\x13\xca'):
                    self.eapol_message3_list.append(self.packets_eapol[index])
                elif(bytes(self.packets_eapol[index].getlayer(Raw).load)[1:3] == b'\x03\x0a'):
                    self.eapol_message4_list.append(self.packets_eapol[index])

            print('[-]     Number of EAPOL Message 1 frames found: {}'.format(len(self.eapol_message1_list)))
            print('[-]     Number of EAPOL Message 2 frames found: {}'.format(len(self.eapol_message2_list)))
            print('[-]     Number of EAPOL Message 3 frames found: {}'.format(len(self.eapol_message3_list)))
            print('[-]     Number of EAPOL Message 4 frames found: {}'.format(len(self.eapol_message4_list)))
        except Exception as e:
            print('Error:\r\n{}'.format(e))
            return False
        return True

    @classmethod
    def pcapReader(self):
        try:
            self.in_file_pcap=rdpcap(self.packets_filename)
        except Exception as e:
            print('Error:\r\n{}'.format(e))
            return False
        print('[+] Number of frames read from \'{}\': {}'.format(self.packets_filename, len(self.in_file_pcap)))
        if(self.extractFrames() != True):
            return False
        self.techniqueAssessor()
        return True

    @classmethod
    def checkFramePMKIDStatus(self, frame=None):
        fPMKID = b'00000000000000000000000000000000'
        PMKID = binascii.hexlify(frame.getlayer(Raw).load)[202:234]
        if((PMKID != fPMKID) and (PMKID != '') and (frame.getlayer(Dot11).addr3 not in self.eapol_message1_pmkid_bssid)):
            print('[-]     Found a PMKID!')
            self.eapol_message1_pmkid.append(frame)
            self.eapol_message1_pmkid_bssid.append(frame.getlayer(Dot11).addr3)
        elif(frame.getlayer(Dot11).addr3 in self.eapol_message1_pmkid_bssid):
            print('[-]     Duplicate PMKID found, skipping...')

    @classmethod
    def checkBeaconFrame(self, frame=None):
        self.knownBeaconBSSID.clear()
        for beacon in self.packets_beacon:
            self.knownBeaconBSSID.append(beacon.getlayer(Dot11).addr3)
        if((frame.getlayer(Dot11).addr3 not in self.knownBeaconBSSID)):
            print('[-]     Beacon frame \'{}\' was unobserved, forging beacon frame...'.format(frame.getlayer(Dot11).addr3))
            if(frame.haslayer(RadioTap)):
                self.craftBeaconFrame(ssid=self.ssid, bssid=frame.getlayer(Dot11).addr3, RadioTapStatus=True)
            else:
                self.craftBeaconFrame(ssid=self.ssid, bssid=frame.getlayer(Dot11).addr3)
            print('[-]     Forging completed!')
            self.candiate1Status=True
        elif((frame.getlayer(Dot11).addr3 in self.knownBeaconBSSID)):
            print('[-]     candiate Beacon frame found, skipping...')
            self.candiate1Status=True
        return True

    @classmethod
    def craftBeaconFrame(self, ssid=None, bssid=None, RadioTapStatus=False):
        if(RadioTapStatus):
            beaconFrame = \
                RadioTap()\
                /Dot11(type=0,subtype=8,addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid)\
                /Dot11Beacon(cap='ESS+privacy')\
                /Dot11Elt(ID='SSID', info='{}'.format(ssid), len=len(ssid))
        else:
            beaconFrame = \
                Dot11(type=0,subtype=8,addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid)\
                /Dot11Beacon(cap='ESS+privacy')\
                /Dot11Elt(ID='SSID', info='{}'.format(ssid), len=len(ssid))
        return self.packets_beacon.append(beaconFrame)

    @classmethod
    def getBeaconFrame(self, frame):
        for beacon in self.packets_beacon:
            if(beacon.getlayer(Dot11).addr3 == frame.getlayer(Dot11).addr3):
                return beacon

    @classmethod
    def craftEapol1Frame(self, frame=None, RadioTapStatus=False):
        import binascii
        rsn = binascii.unhexlify(b'02008a00100000000000000001ea2f0b186071ed18e9fdc30f6d938cf9250d3df5f1a4abadc454612fddea173d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        if(RadioTapStatus):
            eapol1 = \
                RadioTap()\
                /Dot11FCS(
                    addr1=frame.getlayer(Dot11).addr2, 
                    addr2=frame.getlayer(Dot11).addr1, 
                    addr3=frame.getlayer(Dot11).addr3,
                    FCfield='from-DS', 
                    ID=31233,
                    SC=46144,
                    fcs=0xe57d5e44,
                    proto=0
                    )\
                /LLC(
                    dsap=0xaa,
                    ssap=0xaa,
                    ctrl=3
                    )\
                /SNAP()\
                /EAPOL(
                    version='802.1X-2004',
                    type='EAPOL-Key',
                    )\
                /Raw(load=rsn)
        else:
            eapol1 = \
                Dot11FCS(
                    addr1=frame.getlayer(Dot11).addr2, 
                    addr2=frame.getlayer(Dot11).addr1, 
                    addr3=frame.getlayer(Dot11).addr3,
                    FCfield='from-DS', 
                    ID=31233,
                    SC=46144,
                    fcs=0xe57d5e44,
                    proto=0
                    )\
                /LLC(
                    dsap=0xaa,
                    ssap=0xaa,
                    ctrl=3
                    )\
                /SNAP()\
                /EAPOL(
                    version='802.1X-2004',
                    type='EAPOL-Key',
                    )\
                /Raw(load=rsn)
        return self.craftEapol1FrameList.append(eapol1)

    @classmethod
    def getEapol1Frame(self, frame):
        for eapol1 in self.craftEapol1FrameList:
            if(eapol1.getlayer(Dot11).addr3 == frame.getlayer(Dot11).addr3):
                return eapol1

    @classmethod
    def techniqueCandidate1(self):
        '''
        Produces a repaired PCAP where EAPOL Message 1 contains a PMKID
        but no Beacon frame was recorded.
        '''
        try:
            for frame in self.eapol_message1_list:
                self.checkFramePMKIDStatus(frame=frame)
            print('[-]     Number of PMKID Candiates found: {}'.format(len(self.eapol_message1_pmkid)))
            print('[-]     Checking for relevant candiate Beacon frame')
            for frame in self.eapol_message1_pmkid:
                self.checkBeaconFrame(frame=frame)
                if(self.candiate1Status):
                    output_filename='{}_repaired_candiate_1.pcap'.format(self.packets_filename.split('.')[0])
                    print('[-]     Creating candiate PCAP file: {}'.format(output_filename))
                    wrpcap(output_filename, (self.getBeaconFrame(frame=frame), frame), append=True)
            self.candiate1Status=False
            self.knownBeaconBSSID.clear()
            return True
        except Exception as e:
            print('[!]    Error: {}'.format(e))
            return False

    @classmethod
    def techniqueCandidate2(self):
        '''
        Produces a repaired PCAP where EAPOL Message 1+Message2 sequence was recorded
        but no Beacon frame was recorded.
        '''
        try:
            self.knownMessage1 = []
            self.knownMessage1BSSID = []
            self.knownMessage2 = []
            self.knownMessage2BSSID = []
            self.EAPOLknownPairsBSSID = []
            print('[-]     Removing duplicate EAPOL Message 1 frames...')
            for message1 in self.eapol_message1_list:
                if(message1.getlayer(Dot11).addr3 not in self.knownMessage1BSSID):
                    print('[-]     Found new EAPOL Message 1, adding to list...')
                    self.knownMessage1BSSID.append(message1.getlayer(Dot11).addr3)
                    self.knownMessage1.append(message1)
                elif(message1.getlayer(Dot11).addr3 in self.knownMessage1BSSID):
                    print('[-]     Duplicate EAPOL Message 1 found, skipping...')

            print('[-]     Removing duplicate EAPOL Message 2 frames...')
            for message2 in self.eapol_message2_list:
                if(message2.getlayer(Dot11).addr3 not in self.knownMessage2BSSID):
                    print('[-]     Found new EAPOL Message 2, adding to list...')
                    self.knownMessage2BSSID.append(message2.getlayer(Dot11).addr3)
                    self.knownMessage2.append(message2)
                elif(message2.getlayer(Dot11).addr3 in self.knownMessage2BSSID):
                    print('[-]     Duplicate EAPOL Message 2 found, skipping...')

            print('[-]     Checking for EAPOL Message 1 and Message 2 pairs')
            for message1 in self.knownMessage1:
                for message2 in self.knownMessage2:
                    if((message1.getlayer(Dot11).addr3 == message2.getlayer(Dot11).addr3) and (message1.getlayer(Dot11).addr3 not in self.EAPOLknownPairsBSSID)):
                        print('[-]     Pair found!')
                        self.EAPOLknownPairsBSSID.append(message1.getlayer(Dot11).addr3)
                        self.checkBeaconFrame(frame=message1)
                        if(self.candiate1Status):
                            output_filename='{}_repaired_candiate_2.pcap'.format(self.packets_filename.split('.')[0])
                            print('[-]     Creating candiate PCAP file: {}'.format(output_filename))
                            wrpcap(output_filename, (self.getBeaconFrame(frame=message1), message1, message2), append=True)

                    else:
                        print('[-]     No pairs found!')
                        return False

            self.candiate1Status=False
            self.knownMessage1.clear()
            self.knownMessage1BSSID.clear()
            self.knownMessage2.clear()
            self.knownMessage2BSSID.clear()
            self.EAPOLknownPairsBSSID.clear()
            return True
        except Exception as e:
            print('[!]    Error: {}'.format(e))
            return False

    @classmethod
    def techniqueCandidate3(self):
        '''
        Produces a repaired PCAP where EAPOL Message 2+Message3 sequence was recorded
        but no Beacon frame was recorded, inserts a fake EAPOL Message 1 Frame.
        '''
        try:
            self.knownMessage2 = []
            self.knownMessage2BSSID = []
            self.knownMessage3 = []
            self.knownMessage3BSSID = []
            print('[-]     Removing duplicate EAPOL Message 2 frames...')
            for message2 in self.eapol_message2_list:
                if(message2.getlayer(Dot11).addr3 not in self.knownMessage2BSSID):
                    print('[-]     Found new EAPOL Message 2, adding to list...')
                    self.knownMessage2BSSID.append(message2.getlayer(Dot11).addr3)
                    self.knownMessage2.append(message2)
                elif(message2.getlayer(Dot11).addr3 in self.knownMessage2BSSID):
                    print('[-]     Duplicate EAPOL Message 2 found, skipping...')

            print('[-]     Removing duplicate EAPOL Message 3 frames...')
            for message3 in self.eapol_message3_list:
                if(message3.getlayer(Dot11).addr3 not in self.knownMessage3BSSID):
                    print('[-]     Found new EAPOL Message 3, adding to list...')
                    self.knownMessage3BSSID.append(message3.getlayer(Dot11).addr3)
                    self.knownMessage3.append(message3)
                elif(message3.getlayer(Dot11).addr3 in self.knownMessage3BSSID):
                    print('[-]     Duplicate EAPOL Message 3 found, skipping...')

            print('[-]     Checking for EAPOL Message 2 and Message 3 pairs')
            self.EAPOLknownPairsBSSID = []
            for message2 in self.knownMessage2:
                for message3 in self.knownMessage3:
                    if((message2.getlayer(Dot11).addr3 == message3.getlayer(Dot11).addr3) and (message2.getlayer(Dot11).addr3 not in self.EAPOLknownPairsBSSID)):
                        print('[-]     Pair found!')
                        self.EAPOLknownPairsBSSID.append(message2.getlayer(Dot11).addr3)
                        self.checkBeaconFrame(frame=message2)
                        if(message2.haslayer(RadioTap)):
                            self.craftEapol1Frame(frame=message2, RadioTapStatus=True)
                        else:
                            self.craftEapol1Frame(frame=message2)
                        if(self.candiate1Status):
                            output_filename='{}_repaired_candiate_3.pcap'.format(self.packets_filename.split('.')[0])
                            print('[-]     Creating candiate PCAP file: {}'.format(output_filename))
                            wrpcap(output_filename, (self.getBeaconFrame(frame=message2), self.getEapol1Frame(frame=message2), message2, message3), append=True)

                    else:
                        print('[-]     No pairs found!')
                        return False

            self.candiate1Status=False
            self.EAPOLknownPairsBSSID.clear()
            self.knownMessage2.clear()
            self.knownMessage2BSSID.clear()
            self.knownMessage3.clear()
            self.knownMessage3BSSID.clear()
            return True
        except Exception as e:
            print('[!]    Error: {}'.format(e))
            return False

    @classmethod
    def techniqueAssessor(self):
        print('[-]\r\n[+] Evaulation Repair Techniques')

        if(self.PerformTechniqueCandidate1):
            print('[-]   Candiate Technique 1: Checking for EAPOL Message 1 Frames for PMKID')
            if(self.techniqueCandidate1()):
                print('[-]   Candiate Technique 1: Success')
                if((not self.PerformTechniqueAll) and (not self.PerformTechniqueCandidate2) and (not self.PerformTechniqueCandidate3)):
                    return True
            else:
                print('[-]   Candiate Technique 1: Failed')
        print('[-]')
        if(self.PerformTechniqueCandidate2):
            print('[-]   Candiate Technique 2: Checking for EAPOL Message 1+Message 2 Pair Sequence')
            if(self.techniqueCandidate2()):
                print('[-]   Candiate Technique 2: Success')
                if((not self.PerformTechniqueAll) and (not self.PerformTechniqueCandidate2) and (not self.PerformTechniqueCandidate3)):
                    return True
            else:
                print('[-]   Candiate Technique 2: Failed')
        print('[-]')
        if(self.PerformTechniqueCandidate3):
            print('[-]   Candiate Technique 3: Checking for EAPOL Message 2+Message 3 Pair Sequence')
            if(self.techniqueCandidate3()):
                print('[-]   Candiate Technique 3: Success')
                if((not self.PerformTechniqueAll) and (not self.PerformTechniqueCandidate2) and (not self.PerformTechniqueCandidate3)):
                    return True
            else:
                print('[-]   Candiate Technique 3: Failed')
        print('[-]\r\n[+] Evaulation Repair Techniques finished!')

if __name__ == '__main__':
    options = optionsFunc()

    rh = repairHandshake(
        packets_filename=options['in_file'],
        ssid=options['SSID'],
        PerformTechniqueAll=options['PerformTechniqueAll'],
        PerformTechniqueCandidate1=options['enableTechnique1'],
        PerformTechniqueCandidate2=options['enableTechnique2'],
        PerformTechniqueCandidate3=options['enableTechnique3']
        )
    rh.pcapReader()

    sys.exit(0)
