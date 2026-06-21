#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
#include <vector>

class Scanner {
public:
    Scanner();
    ~Scanner();

    // Runs whatever techniques are currently toggled inside g_scan.options
    void run(const std::string& target_ip, const std::vector<unsigned short>& ports);

    void printSummaryMatrix(const std::vector<unsigned short>& ports);
};

#endif