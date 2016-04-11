#ifndef LLDP_BEACON_HEAD_H

#include <iostream>
#include <string>
#include <stdio.h>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <regex>
#include <set>
#include <map>
#include <iomanip>
#include <ctime>
#include <windef.h>
#include <Windows.h>
#include <iptypes.h>
#include <ipifcons.h>
#include <Iphlpapi.h>
#include <unistd.h>
#include <winsock.h>
#include <wininet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "dpcap.h"

using namespace std;

map<string, string> wmic(string alias);

std::string exec(const char *cmd);

void loop(string hostname, string osname);

void md_install_service();

void md_service_control(DWORD dwControl);

void md_service_main(DWORD argc, char **argv);

void md_remove_service();

void interrupt();

basic_ostream<char> *_dbg(const char *func, int line);

void _dbg_cfg(bool enabled);

#define dbg (*_dbg(__FUNCTION__, __LINE__))

#define LLDP_BEACON_HEAD_H

#endif //LLDP_BEACON_HEAD_H
