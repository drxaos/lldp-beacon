# lldp-beacon
Simple LLDP beacon for win32/64 (no discovery)

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
lldp-beacon -d -h <host name> -s <system name>
```
* ```-d``` - enable debug logging
* ```-h <host name>``` - use this hostname; if not present - hostname will be taken from wmic
* ```-s <system name>``` - use this OS name; if not present - OS name will be taken from wmic

## Install as service
Copy lldp-beacon.exe to a new directory (e.g. C:\Program Files\lldp-beacon).

Run command:
```
lldp-beacon.exe --install
```

Hostname and OS name will be taken from wmic
