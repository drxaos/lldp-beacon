# lldp-beacon
Simple LLDP beacon for win32/64 (no discovery)

https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol

## Requirements
* WinPcap http://www.winpcap.org/
* wmic + Running WMI Service

## Build tools
* MinGW (gcc, g++, mingw32-make) http://www.mingw.org/
* CMake https://cmake.org/

## Build

Download project:
```
git clone https://github.com/drxaos/lldp-beacon.git
```

Go to build folder:
```
cd lldp-beacon/build
```

Configure:
```
cmake -G "MinGW Makefiles" ..
```

Build .exe file:
```
make
```

## Running
```
lldp-beacon -h <host name> -s <system name>
```
* ```-h <host name>``` - use this hostname; if not present - hostname will be taken from wmic
* ```-s <system name>``` - use this OS name; if not present - OS name will be taken from wmic

LLDP packets are sent to all interfaces every 30 seconds

![wireshark](https://github.com/drxaos/lldp-beacon/blob/master/doc/wireshark.png)

![debug](https://github.com/drxaos/lldp-beacon/blob/master/doc/debug.png)

![perf](https://github.com/drxaos/lldp-beacon/blob/master/doc/perf.png)

## Install as windows service

Copy lldp-beacon.exe to a new directory (e.g. C:\Program Files\lldp-beacon).

Run command:
```
lldp-beacon.exe install
```

Hostname and OS name will be taken from wmic

To remove service run command:
```
lldp-beacon.exe remove
```
