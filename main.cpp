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
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        u_char packet[100];
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

            // TODO

            /* Send down the packet */
            if (pcap_sendpacket(fp, packet, 100 /* size */) != 0) {
                fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
            }

            pcap_close(fp);
        }
        pAdapterInfo = pAdapterInfo->Next;
    }
}

int main() {
    std::map<std::string, std::string> info = wmic();
    cout << info["CSName"] << endl;
    cout << info["Caption"] << endl;
    cout << info["RegisteredUser"] << endl;

    while (true) {
        iterate_devs(info["CSName"], info["Caption"]);
        sleep(1);
    }

    return 0;
}

#define IPTOSBUFFERS    12

char *iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char *p;

    p = (u_char *) &in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
