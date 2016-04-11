#include "head.h"

map<int, string> ptrcache;
HINSTANCE dllHandle;
dll_pcap_open pcap_open;
dll_pcap_close pcap_close;
dll_pcap_sendpacket pcap_sendpacket;
dll_pcap_geterr pcap_geterr;

void lldp(std::string hostname, std::string osname) {
    IP_ADAPTER_INFO AdapterInfo[32];       // Allocate information for up to 32 NICs
    DWORD dwBufLen = sizeof(AdapterInfo);  // Save memory size of buffer
    dbg << "Searching adapters";
    DWORD dwStatus = GetAdaptersInfo(      // Call GetAdapterInfo
            AdapterInfo,                 // [out] buffer to receive data
            &dwBufLen);                  // [in] size of receive data buffer

    //No network card? Other error?
    if (dwStatus != ERROR_SUCCESS) {
        dbg << "Unknown error (No network card?)";
        return;
    }

    int sentCount = 0;

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    while (pAdapterInfo) {
        dbg << "Next adapter: " << pAdapterInfo->Description;
        IP_ADDRESS_STRING ipaddress = pAdapterInfo->IpAddressList.IpAddress;
        if (&ipaddress == nullptr || strlen(ipaddress.String) < 7 || strcmp(ipaddress.String, "0.0.0.0") == 0) {
            dbg << "Incorrect IP: " << ipaddress.String;
            pAdapterInfo = pAdapterInfo->Next;
            continue;
        }
        dbg << "Parsing IP: " << ipaddress.String;
        int ip1, ip2, ip3, ip4;
        char dot;
        istringstream s(ipaddress.String);  // input stream that now contains the ip address string
        s >> ip1 >> dot >> ip2 >> dot >> ip3 >> dot >> ip4 >> dot;

        string dnsdomain = ptrcache[pAdapterInfo->Index];
        if (dnsdomain.empty()) {
            dbg << "Searching dns name for " << ipaddress.String;
            map<string, string> info = wmic(
                    string("nicconfig WHERE InterfaceIndex=") + to_string(pAdapterInfo->Index));
            dnsdomain = info["DNSDomain"];
            if (dnsdomain.empty()) {
                dbg << "DNS name not found, using hostname";
                dnsdomain = hostname;
            }
            ptrcache[pAdapterInfo->Index] = dnsdomain;
        }

        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        u_char packet[1024];
        int i;

        string rpcap = "rpcap://\\Device\\NPF_";
        rpcap.append(pAdapterInfo->AdapterName);

        dbg << "Open pcap: " << rpcap;
        if ((fp = pcap_open(rpcap.c_str(),
                            100,                // portion of the packet to capture (only the first 100 bytes)
                            PCAP_OPENFLAG_NOCAPTURE_RPCAP,
                            1000,               // read timeout
                            NULL,               // authentication on the remote machine
                            errbuf              // error buffer
        )) == NULL) {
            dbg << "Unable to open the adapter. " << rpcap.c_str() << " is not supported by WinPcap";
        } else {
            dbg << "Building packet";

            // LLDP_MULTICAST
            packet[0] = 0x01;
            packet[1] = 0x80;
            packet[2] = 0xc2;
            packet[3] = 0x00;
            packet[4] = 0x00;
            packet[5] = 0x0e;

            // SRC MAC
            dbg << "Building packet: SRC MAC: " << hex
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[0] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[1] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[2] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[3] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[4] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[5] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[6]
            << dec << setw(1);

            packet[6] = pAdapterInfo->Address[0];
            packet[7] = pAdapterInfo->Address[1];
            packet[8] = pAdapterInfo->Address[2];
            packet[9] = pAdapterInfo->Address[3];
            packet[10] = pAdapterInfo->Address[4];
            packet[11] = pAdapterInfo->Address[5];

            // ETHERNET_TYPE_LLDP
            packet[12] = 0x88;
            packet[13] = 0xcc;

            int counter = 14;

            // CHASSIS SUBTYPE
            dbg << "Building packet: CHASSIS SUBTYPE: " << dnsdomain;
            packet[counter++] = 0x02; // chassis id
            packet[counter++] = (u_char) (dnsdomain.length() + 1);
            packet[counter++] = 0x07; // locally assigned
            for (int j = 0; j < dnsdomain.length(); ++j) {
                packet[counter++] = (u_char) dnsdomain.c_str()[j];
            }

            // PORT SUBTYPE
            dbg << "Building packet: PORT SUBTYPE: " << hex
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[0] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[1] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[2] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[3] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[4] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[5] << ":"
            << setfill('0') << setw(2) << (int) pAdapterInfo->Address[6]
            << dec << setw(1);

            packet[counter++] = 0x04; // port id
            packet[counter++] = 0x07; // size 1+6
            packet[counter++] = 0x03; // type = mac address
            for (int j = 0; j < 6; ++j) {
                packet[counter++] = pAdapterInfo->Address[j];
            }

            // TTL
            packet[counter++] = 0x06; // TTL
            packet[counter++] = 0x02; // size 1+1
            packet[counter++] = 0x00; // 120 sec
            packet[counter++] = 120;

            // Port description
            dbg << "Building packet: Port Desc: " << pAdapterInfo->Description;
            packet[counter++] = 0x08; // Port Description
            int descLen = strlen(pAdapterInfo->Description);
            packet[counter++] = (u_char) descLen; // Description length
            for (int j = 0; j < descLen; ++j) {
                packet[counter++] = (u_char) pAdapterInfo->Description[j];
            }

            // System name
            dbg << "Building packet: Sys Name: " << dnsdomain;
            packet[counter++] = 0x0a; // System name
            packet[counter++] = (u_char) dnsdomain.length(); // Name length
            for (int j = 0; j < dnsdomain.length(); ++j) {
                packet[counter++] = (u_char) dnsdomain.c_str()[j];
            }

            // System description
            dbg << "Building packet: Sys Desc: " << osname;
            packet[counter++] = 0x0c; // System desc
            packet[counter++] = (u_char) osname.length(); // Name length
            for (int j = 0; j < osname.length(); ++j) {
                packet[counter++] = (u_char) osname.c_str()[j];
            }

            // Caps
            packet[counter++] = 0x0e; // Sys caps
            packet[counter++] = 0x04; // size 2+2
            packet[counter++] = 0x00; //
            packet[counter++] = 0x80; // station only
            packet[counter++] = 0x00; //
            packet[counter++] = 0x80; // station only

            // Management address
            packet[counter++] = 0x10; // Management addr
            packet[counter++] = 0x0c; // size 12
            packet[counter++] = 0x05; // addr len 1+4
            packet[counter++] = 0x01; // addr subtype: ipv4
            packet[counter++] = (u_char) ip1; // ip
            packet[counter++] = (u_char) ip2; // ip
            packet[counter++] = (u_char) ip3; // ip
            packet[counter++] = (u_char) ip4; // ip

            dbg << "Building packet: if subtype: ifIndex: " << pAdapterInfo->Index;
            packet[counter++] = 0x02; // if subtype: ifIndex
            BYTE *pbyte = (BYTE *) &(pAdapterInfo->Index);
            packet[counter++] = pbyte[3]; // id
            packet[counter++] = pbyte[2]; // id
            packet[counter++] = pbyte[1]; // id
            packet[counter++] = pbyte[0]; // id

            packet[counter++] = 0x00; // oid len 0

            // IEEE 802.3 - MAC/PHY Configuration/Status
            packet[counter++] = 0xfe; //
            packet[counter++] = 0x09; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x12; //
            packet[counter++] = 0x0f; //
            packet[counter++] = 0x01; //
            packet[counter++] = 0x02; //
            packet[counter++] = 0x80; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x1e; //

            // IEEE 802.3 - Maximum Frame Size
            packet[counter++] = 0xfe; //
            packet[counter++] = 0x06; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x12; //
            packet[counter++] = 0x0f; //
            packet[counter++] = 0x04; //
            packet[counter++] = 0x05; //
            packet[counter++] = 0xee; //

            // TIA TR-41 Committee - Media Capabilities
            packet[counter++] = 0xfe; //
            packet[counter++] = 0x07; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x12; //
            packet[counter++] = 0xbb; //
            packet[counter++] = 0x01; //
            packet[counter++] = 0x01; //
            packet[counter++] = 0xee; //
            packet[counter++] = 0x03; //

            // TIA TR-41 Committee - Network Policy
            packet[counter++] = 0xfe; //
            packet[counter++] = 0x08; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x12; //
            packet[counter++] = 0xbb; //
            packet[counter++] = 0x02; //
            packet[counter++] = 0x06; //
            packet[counter++] = 0x80; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x00; //

            // TIA TR-41 Committee - Network Policy
            packet[counter++] = 0xfe; //
            packet[counter++] = 0x08; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x12; //
            packet[counter++] = 0xbb; //
            packet[counter++] = 0x02; //
            packet[counter++] = 0x07; //
            packet[counter++] = 0x80; //
            packet[counter++] = 0x00; //
            packet[counter++] = 0x00; //

            // End of LLDPDU
            packet[counter++] = 0x00; // type
            packet[counter++] = 0x00; // len 0

            /* Send down the packet */
            dbg << "Sending packet (size: " << counter << ")";
            if (pcap_sendpacket(fp, packet, counter /* size */) != 0) {
                fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
            } else {
                sentCount++;
            }

            dbg << "Closing pcap";
            pcap_close(fp);
        }
        pAdapterInfo = pAdapterInfo->Next;
    }
    if (sentCount > 0) {
        dbg << "Successfully sent " << sentCount << " packets";
    } else {
        dbg << "Packets not sent!";
    }
}

void wait(basic_ostream<char> *progress, int sec) {
    *progress << "Sleeping " << sec << "sec";
    for (int i = 0; i < sec; ++i) {
        sleep(1);
        *progress << ".";
    }
}

void loadpcap() {
    dllHandle = LoadLibrary("wpcap.dll");
    if (!dllHandle) {
        cerr << "Trying to install WinPcap.exe";
        exec("winpcap.exe /S");
        dllHandle = LoadLibrary("wpcap.dll");
        if (!dllHandle) {
            cerr << "Cannot install WinPcap";
            exit(1);
        }
    }

    pcap_open = (dll_pcap_open) GetProcAddress(dllHandle, "pcap_open");
    pcap_close = (dll_pcap_close) GetProcAddress(dllHandle, "pcap_close");
    pcap_sendpacket = (dll_pcap_sendpacket) GetProcAddress(dllHandle, "pcap_sendpacket");
    pcap_geterr = (dll_pcap_geterr) GetProcAddress(dllHandle, "pcap_geterr");
}

int main(int argc, char *argv[]) {

    loadpcap();

    string hostname;
    string osname;

    for (int i = 0; i < argc; ++i) {
        std::string s(argv[i]);
        if (s.find("-d") == 0) {
            _dbg_cfg(true);
            dbg << "Debug logging enabled";
        }
    }
    for (int i = 0; i < argc; ++i) {
        std::string s(argv[i]);
        if (s.find("-h") == 0) {
            hostname = s;
            dbg << "Set hostname = " << hostname;
        }
    }
    for (int i = 0; i < argc; ++i) {
        std::string s(argv[i]);
        if (s.find("-s") == 0) {
            osname = s;
            dbg << "Set systemname = " << hostname;
        }
    }

    if (hostname.empty() || osname.empty()) {
        std::map<std::string, std::string> info;
        info = wmic("os");
        if (hostname.empty()) {
            hostname = info["CSName"];
        }
        if (osname.empty()) {
            osname = info["Caption"] + " " + info["OSArchitecture"] + " " + info["Version"];
        }
    }

    dbg << "Hostname: " << hostname;
    dbg << "OS name: " << osname;

    while (true) {
        lldp(hostname, osname);
        wait(&(dbg), 30);
    }

    return 0;
}
