//
// Created by Administrator on 4/11/16.
//

#ifndef LLDP_BEACON_DPCAP_H_H
#define LLDP_BEACON_DPCAP_H_H

typedef struct pcap pcap_t;

typedef int (__stdcall *f_funci)();

#define PCAP_ERRBUF_SIZE 256
#define PCAP_OPENFLAG_NOCAPTURE_RPCAP    4

typedef pcap_t *(__stdcall *dll_pcap_open)(
        const char *source, int snaplen, int flags, int read_timeout,
        struct pcap_rmtauth *auth, char *errbuf);

typedef void (__stdcall *dll_pcap_close)(pcap_t *);

typedef int (__stdcall *dll_pcap_sendpacket)(pcap_t *, const u_char *, int);

typedef char *(__stdcall *dll_pcap_geterr)(pcap_t *);


#endif //LLDP_BEACON_DPCAP_H_H
