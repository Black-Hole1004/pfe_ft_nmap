#include "gui_widgets.hpp"
#include "imgui.h"
#include "functions.hpp"
#include "scanner.hpp"
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>

static char target_ip_buf[128] = "127.0.0.1";
static char ports_buf[512] = "80,443,22,21";
static std::vector<std::string> ui_logs;
static std::mutex log_mutex;
static bool is_scanning = false;

void LogToConsole(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    ui_logs.push_back(message);
}


void RunScanWorker(std::string target_ip, std::vector<unsigned short> parsed_ports) {
    Scanner scanner;
    LogToConsole("[+] Executing scanner engine run loop...");
    scanner.run(target_ip, parsed_ports);
    LogToConsole("[+] Scan complete! Generating matrix summary...");
    // Future expansion: we can capture or parse results here for charts
    //
    //

    if (g_scan.handle) {
        pcap_close(g_scan.handle);
        g_scan.handle = nullptr;
    }
    free_IPs();
    
    is_scanning = false;
}

void RenderScannerUI() {
    ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(550, 680), ImGuiCond_FirstUseEver);
    
    ImGui::Begin("pfe_ft_nmap - Control Panel");

    ImGui::InputText("Target IP", target_ip_buf, IM_ARRAYSIZE(target_ip_buf));
    ImGui::InputText("Ports", ports_buf, IM_ARRAYSIZE(ports_buf));
    
    ImGui::Separator();
    ImGui::Text("Scan Techniques:");

    ImGui::Checkbox("SYN Scan (-sS)", &g_scan.options.technique[SYN]); ImGui::SameLine();
    ImGui::Checkbox("ACK Scan (-sA)", &g_scan.options.technique[ACK]); ImGui::SameLine();
    ImGui::Checkbox("FIN Scan (-sF)", &g_scan.options.technique[FIN]);
    
    ImGui::Checkbox("NULL Scan (-sN)", &g_scan.options.technique[NUL]); ImGui::SameLine();
    ImGui::Checkbox("XMAS Scan (-sX)", &g_scan.options.technique[XMAS]); ImGui::SameLine();
    ImGui::Checkbox("UDP Scan (-sU)", &g_scan.options.technique[UDP]);

    ImGui::Separator();
    
    int temp_thread_count = static_cast<int>(g_scan.options.thread_count);
    if (temp_thread_count < 1) temp_thread_count = 1;
    if (ImGui::SliderInt("Worker Thread Pool Count", &temp_thread_count, 1, 6)) {
        g_scan.options.thread_count = static_cast<unsigned short>(temp_thread_count);
    }
    
    ImGui::Separator();

    if (is_scanning) {
        ImGui::Button("Scan Active...", ImVec2(-1, 40));
    } else {
        if (ImGui::Button("Launch Port Scan", ImVec2(-1, 40))) {
            is_scanning = true;
            ui_logs.clear();
            LogToConsole("[+] Initializing scan environment...");

            // 1. Calculate active scan techniques selection
            g_scan.options.technique_count = 0;
            for (int i = 0; i < TECHNIQUE_COUNT; i++) {
                if (g_scan.options.technique[i]) g_scan.options.technique_count++;
            }
            if (g_scan.options.technique_count == 0) {
                g_scan.options.technique[SYN] = true;
                g_scan.options.technique_count = 1;
                LogToConsole("[-] No scan types selected. Defaulting to SYN scan.");
            }

            // 2. Parse ports array list buffer string
            std::vector<unsigned short> parsed_ports;
            std::string ports_str(ports_buf);
            std::stringstream ss(ports_str);
            std::string token;
            
            std::memset(g_scan.options.port, 0, sizeof(g_scan.options.port));
            g_scan.options.port_count = 0;
            
            while (std::getline(ss, token, ',')) {
                if (!token.empty()) {
                    unsigned short p = (unsigned short)std::stoi(token);
                    parsed_ports.push_back(p);
                    g_scan.options.port[p] = true;
                    g_scan.options.port_count++;
                }
            }

            g_scan.options.family = AF_INET;
            g_scan.options.verbose = 0;

            // Resolve target IP and bind to global registry list
            t_IP target = resolve_target(target_ip_buf);
            add_IP(target);

            // Fetch physical hardware device network parameters
            g_scan.interface = get_interface();

            // Thread count clamping calculation bounds
            if (g_scan.options.thread_count < g_scan.options.technique_count)
                g_scan.options.thread_count = g_scan.options.technique_count;
            if (g_scan.options.thread_count > g_scan.options.port_count * g_scan.options.technique_count)
                g_scan.options.thread_count = g_scan.options.port_count * g_scan.options.technique_count;
            if (g_scan.options.thread_count == 0)
                g_scan.options.thread_count = 1;

            // 4. Open Network Device Packet Capture Handle
            std::string device = find_pcap_device(target_ip_buf);
            if (device.empty()) {
                LogToConsole("[-] Error: No suitable pcap device found.");
                free_IPs();
                is_scanning = false;
            } else {
                char errbuf[PCAP_ERRBUF_SIZE] = {0};
                g_scan.handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
                
                if (!g_scan.handle) {
                    std::string err_msg = "[-] pcap_open_live error: ";
                    err_msg += errbuf;
                    LogToConsole(err_msg);
                    free_IPs();
                    is_scanning = false;
                } else {
                    char filter[BUFSIZ] = {0};
                    for (t_IP *ip = g_scan.ip; ip != NULL; ip = ip->next) {
                        char ip_str[INET6_ADDRSTRLEN] = {0};
                        inet_ntop(g_scan.options.family,
                                  g_scan.options.family == AF_INET ? (void*)&ip->addr.ipv4.sin_addr : (void*)&ip->addr.ipv6.sin6_addr,
                                  ip_str, sizeof(ip_str));
                        std::strcat(filter, "host ");
                        std::strcat(filter, ip_str);
                        if (ip->next) std::strcat(filter, " or ");
                    }

                    struct bpf_program fp = {0};
                    if (pcap_compile(g_scan.handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
                        pcap_setfilter(g_scan.handle, &fp) == -1) {
                        LogToConsole("[-] Error: Failed to set pcap compilation filters.");
                        pcap_close(g_scan.handle);
                        free_IPs();
                        is_scanning = false;
                    } else {
                        pcap_freecode(&fp);
                        std::thread worker(RunScanWorker, std::string(target_ip_buf), parsed_ports);
                        worker.detach();
                    }
                }
            }
        }
    }
    ImGui::End();

    // Console Logging Stream Window Right Side
    ImGui::SetNextWindowPos(ImVec2(580, 10), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(680, 680), ImGuiCond_FirstUseEver);
    ImGui::Begin("Live Scanner Console Logs");
    ImGui::BeginChild("LogScroller");
    
    std::lock_guard<std::mutex> lock(log_mutex);
    for (const auto& log : ui_logs) {
        ImGui::TextUnformatted(log.c_str());
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
        
    ImGui::EndChild();
    ImGui::End();
}