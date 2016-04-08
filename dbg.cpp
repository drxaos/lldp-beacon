#include "head.h"

//#ifdef DEBUG

basic_ostream<char> *_dbg(const char *func, int line) {
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, 80, "%d-%m-%Y %I:%M:%S", timeinfo);
    std::string timeStr(buffer);

    cout << endl << "[" << timeStr << "] " << func << "(" << line << "): ";

    return &cout;
}


//#else

//#endif