#include <windef.h>
#include <Windows.h>
#include <iptypes.h>
#include <ipifcons.h>
#include <Iphlpapi.h>
#include <unistd.h>

#include "wmic.cpp"
#include "pcap.h"

// Function prototypes
void sendtodev(pcap_if_t *d);

char *iptos(u_long in);

void iterate_devs(std::string hostname, std::string osname) {
    IP_ADAPTER_INFO AdapterInfo[32];       // Allocate information for up to 32 NICs
    DWORD dwBufLen = sizeof(AdapterInfo);  // Save memory size of buffer
    DWORD dwStatus = GetAdaptersInfo(      // Call GetAdapterInfo
            AdapterInfo,                 // [out] buffer to receive data
            &dwBufLen);                  // [in] size of receive data buffer

    //No network card? Other error?
    if (dwStatus != ERROR_SUCCESS)
        return;

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    while (pAdapterInfo) {
        IP_ADDRESS_STRING ipaddress = pAdapterInfo->IpAddressList.IpAddress;
        if (&ipaddress == nullptr || strlen(ipaddress.String) < 7) {
            continue;
        }
        int ip1, ip2, ip3, ip4;
        char dot;
        istringstream s(ipaddress.String);  // input stream that now contains the ip address string
        s >> ip1 >> dot >> ip2 >> dot >> ip3 >> dot >> ip4 >> dot;

        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        u_char packet[1024];
        int i;

        string rpcap = "rpcap://\\Device\\NPF_";
        rpcap.append(pAdapterInfo->AdapterName);

        if ((fp = pcap_open(rpcap.c_str(),
                            100,                // portion of the packet to capture (only the first 100 bytes)
                            PCAP_OPENFLAG_NOCAPTURE_RPCAP,
                            1000,               // read timeout
                            NULL,               // authentication on the remote machine
                            errbuf              // error buffer
        )) == NULL) {
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", rpcap.c_str());
        } else {
            cout << "Sending to: " << rpcap << endl;

            // LLDP_MULTICAST
            packet[0] = 0x01;
            packet[1] = 0x80;
            packet[2] = 0xc2;
            packet[3] = 0x00;
            packet[4] = 0x00;
            packet[5] = 0x0e;

            // SRC MAC
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
            packet[counter++] = 0x02; // chassis id
            packet[counter++] = (u_char) (hostname.length() + 1);
            packet[counter++] = 0x07; // locally assigned
            for (int j = 0; j < hostname.length(); ++j) {
                packet[counter++] = (u_char) hostname.c_str()[j];
            }

            // PORT SUBTYPE
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
            packet[counter++] = 0x08; // Port Description
            int descLen = strlen(pAdapterInfo->Description);
            packet[counter++] = (u_char) descLen; // Description length
            for (int j = 0; j < descLen; ++j) {
                packet[counter++] = (u_char) pAdapterInfo->Description[j];
            }

            // System name
            packet[counter++] = 0x0a; // System name
            packet[counter++] = (u_char) hostname.length(); // Name length
            for (int j = 0; j < hostname.length(); ++j) {
                packet[counter++] = (u_char) hostname.c_str()[j];
            }

            // System description
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
            if (pcap_sendpacket(fp, packet, counter /* size */) != 0) {
                fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
            }

            pcap_close(fp);
        }
        pAdapterInfo = pAdapterInfo->Next;
    }
}

int main() {
    std::map<std::string, std::string> info = wmic();
    cout << "Hostname: " << info["CSName"] << endl;
    cout << "Username: " << info["RegisteredUser"] << endl;
    cout << "OS: " << info["Caption"] << endl;

    while (true) {
        cout << endl << "Searching adapters..." << endl;
        iterate_devs(info["CSName"], info["Caption"]);
        sleep(1);
    }

    return 0;
}
