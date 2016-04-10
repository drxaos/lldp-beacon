#include "head.h"

std::string trim(const std::string &str, const std::string &whitespace = " \r\n\t") {
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

std::string exec(const char *cmd) {
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);
    return result;
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

map<string, string> wmic(string alias) {
    dbg << "Exec WMIC";
    std::string sysinfo = trim(exec((string("wmic ") + string(alias) + string(" get /value")).c_str()));

    dbg << "WMIC:" << endl << sysinfo;

    dbg << "Parsing WMIC";
    std::map<std::string, std::string> info;
    for (const std::string &tag : split(sysinfo, '\n')) {
        auto key_val = split(trim(tag), '=');
        if (key_val.size() == 2) {
            info.insert(std::make_pair(trim(key_val[0]), trim(key_val[1])));
        }
    }

    return info;
}