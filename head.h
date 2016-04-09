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

#include "pcap.h"

using namespace std;

std::map<std::string, std::string> wmic();

basic_ostream<char> *_dbg(const char *func, int line);
void _dbg_cfg(bool enabled);

#define dbg (*_dbg(__FUNCTION__, __LINE__))

#define LLDP_BEACON_HEAD_H

#endif //LLDP_BEACON_HEAD_H
