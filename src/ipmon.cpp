/*! \file
 * \brief IP address monitor
 */

#include <string>
#include <cstdlib>
#include <sysexits.h>
#include <cstdio>
#include <iomanip>
#include <errno.h>
#include <memory.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <nftables/libnftables.h>
#include <ifaddrs.h>
#include <chrono>
#include <fstream>
#include <signal.h>
#include <sys/time.h>
#include <getopt.h>
#include "ipmon.h"
#include <algorithm>
#include <string>
#include <optional>
#include <mutex>
#include <stdexcept>

std::optional<std::string> atomic_write(const std::string& path, const std::string& content)
{
    std::ofstream ofs;

    try {
        ofs.open(path + ".tmp", std::ofstream::out | std::ofstream::trunc);
    } catch (const std::ios_base::failure& e)
    {
        return "Error opening file at " + path + ".tmp: " + e.what();
    }
    ofs << content;
    try {
        ofs.close();
    } catch (const std::ios_base::failure& e)
    {
        return "Error closing file at " + path + ".tmp: " + e.what();
    }
    if (rename((path + ".tmp").c_str(), path.c_str()) != 0)
        return "Error writing file at " + path + ": " + strerror(errno);
    return std::nullopt;
}

void log_and_aleep(std::optional<std::string> msg = std::nullopt) {
    if (msg)
        std::cerr << *msg << (errno ? strerror(errno) : "") <<  std::endl;
    std::this_thread::sleep_for(std::chrono::microseconds(250'000));
}

void ipmon::help()
{
    std::cout << R"( Usage: ipmon [-n[FILE] | --nftables[=FILE] [-f | --flush]] [-p[FILE] | --proxy[=FILE]]
                                  [-d DELAY | --delay=DELAY] [-m | --monitor] [-h | --help]
                                  [-s | --start]

    -h, --help         ... Displays a help message.
    -n, --nftables     ... Updates addresses for nftables
    -f, --flush        ... Used with -n, flushes the nftables ruleset and reloads them
    -p, --proxy        ... Updates addresses for proxy
    -d, --delay        ... Delay for updating the changes, 1-99 seconds or 100-999999 microseconds, defaults to 200000
    -m, --monitor      ... Monitors the netlink for address related events, writing them to stdout
    -s, --start        ... Updates addresses at program start

    Monitors interfaces for changes on IP addresses. When address is assigned or removed,
    the current addresses assigned to interfaces are updated to configuration files
    of programs specified in command line options, and the running instances of the programs are forced to
    reload the configuration files..

    After ipmon is started, configuration files are created with current addresses.
    For nftables, the default file name (if not specified in FILE) is )" + _nft_outfile + R"( suffixed with .sets/.vars

     )" + nft_outfile_vars() + R"(
    #!/usr/sbin/nft -f
    define enp0s3 = { 192.168.150.52 }
    define enp0s8 = { 192.168.56.2, 192.168.56.3 }
    define lo = { 127.0.0.1 }

     )" + nft_outfile_sets() + R"(
    #!/usr/sbin/nft -f
    set enp0s3_ipv4_address { type ipv4_addr; elements = { 192.168.150.52,   } }
    set enp0s8_ipv4_address { type ipv4_addr; elements = { 192.168.56.2,   } }
    set lo_ipv4_address { type ipv4_addr; elements = { 127.0.0.1,   } }

    It is possible to update running nftables configuration without the need to flush the ruleset.
    This requires using named sets in rule definitions by calling @interface-name instead of $interface-name
    Before such update occurs, @interface-name has the value of $interface-name, taken from the file.
    After address update, named set value is updated, i.e. when enp0s3 will change to 192.168.150.101, 192.168.150.102:

        set enp0s3 {                                            set enp0s3 {
            type ipv4_addr                                          type ipv4_addr
            elements = { $enp0s3 }          ---------->             elements = { 192.168.150.101, 192.168.150.102 }
        }                                                       }

    If parameter --flush is specified, the nftables configuration is always flushed, reloading nftables
    configuration files including the one created by ipmon.

    Parameter --delay specifies the duration between event occured (address changed) and when it is updated.
    Multiple such events usually occur in a row, in which case the update should happen only once.
    Increase this delay if you find ipmon updating configuration multiple times in a very short time.
)" << std::endl;
}


ipmon::ipmon()
    : _socket_server_fd(socket(AF_UNIX, SOCK_DGRAM, 0)),
      _socket_guard(_socket_server_fd.is_valid() ? _socket_server_fd.get() : -1, _socket_server_path)
{
    if (!_socket_server_fd.is_valid()) {
        throw std::runtime_error("SOCKET ERROR: " + std::string(strerror(errno)));
    }

    memset(&_socket_server_addr, 0, sizeof(struct sockaddr_un));
    _socket_server_addr.sun_family = AF_UNIX;
    strcpy(_socket_server_addr.sun_path, _socket_server_path);
    int len = sizeof(_socket_server_addr);
    
    // Unlink the socket path before binding
    if (unlink(_socket_server_path) == -1 && errno != ENOENT) {
        std::cerr << "Error unlinking socket at path " << _socket_server_path << ": " << strerror(errno) << ". Are you running as root?" << std::endl;
    }

    int rc = bind(_socket_server_fd.get(), reinterpret_cast<struct sockaddr*> (&_socket_server_addr), len);
    if (rc == -1) {
        throw std::runtime_error("BIND ERROR: " + std::string(strerror(errno)));
    }
}

ipmon::~ipmon() {
    // FileDescriptor handles closing of file descriptors
}

bool ipmon::init_socket()
{
    // Initialization handled in constructor with exceptions
    return true;
}

void ipmon::listen_socket()
{
    while (true)
    {
        try {
            struct sockaddr_un peer_sock;
            memset(&peer_sock, 0, sizeof(struct sockaddr_un));
            socklen_t peer_len = sizeof(peer_sock);
            char buf[256];
            const auto& peer_sock_p = reinterpret_cast<struct sockaddr*> (&peer_sock);
            if (auto bytes_read = recvfrom(_socket_server_fd.get(), buf, 256, MSG_WAITALL, peer_sock_p, &peer_len);
                bytes_read != -1)
            {
                if (auto buf_view = std::string_view(buf, bytes_read);
                    buf_view == sockserver_cmds.at(sockserver_cmd::reload) ) {
                    reload();
                    if (sendto(_socket_server_fd.get(), nullptr, 0, 0, peer_sock_p, sizeof(peer_sock)) == -1) {
                        log_and_aleep("Listening socket reply error(sendto): ");
                    }
                } else if (buf_view == sockserver_cmds.at(sockserver_cmd::update) ) {
                    update();
                }
                std::this_thread::sleep_for(std::chrono::microseconds(250'000));
            } else if (errno !=  EAGAIN && errno != EWOULDBLOCK) {
                log_and_aleep("Listening socket error(recvfrom): ");
            }
        }
        catch (const std::exception& e) {
            log_and_aleep("Error in listen_socket: " + std::string(e.what()));
            continue;
        }
    }
}

void ipmon::process_cmdline(int argc, char* argv[])
{
    struct option long_options[] =
    {
        {"help",     no_argument,       nullptr, 'h'},
        {"nftables", optional_argument, nullptr, 'n'},
        {"flush",    no_argument,       nullptr, 'f'},
        {"proxy",    optional_argument, nullptr, 'p'},
        {"delay",    required_argument, nullptr, 'd'},
        {"monitor",  no_argument,       nullptr, 'm'},
        {"start",    no_argument,       nullptr, 's'},
        { nullptr, 0, nullptr, 0 }
    };
    static constexpr const char* short_options = "hn::fp::d:ms";
    int c, option_index;
    bool only_root = false;
    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
    {
        switch (c) {
        case 'h':
            help();
            exit(EXIT_SUCCESS);
        case 'n':
            _opt_nftables = true;
            only_root = true;
            if (optarg != nullptr) {
                _nft_outfile = optarg;
            }
            break;
        case 'f':
            _opt_flush = true;
            break;
        case 'p':
            _opt_proxy = true;
            only_root = true;
            break;
        case 'd':
        {
            auto delay = std::stol(optarg);
            if (delay <= 0 || delay > 999999) {
                std::cerr << "Invalid value for parameter --delay: " << delay << std::endl;
                help();
                exit(EX_USAGE);
            } else if (delay < 100) {
                delay *= 1'000'000;
            }
            _delay = std::chrono::microseconds {delay};
            break;
        }
        case 'm':
            _opt_monitor = true;
            break;
        case 's':
            _opt_start = true;
            break;
        default:
            help();
            exit(EX_USAGE);
        }
    }
    if (!_opt_nftables && _opt_flush) {
            help();
            exit(EX_USAGE);
    }
    if (only_root && geteuid() != 0) {
        std::cerr << "You must be root." << std::endl;
        exit(EX_USAGE);
    }
}

void ipmon::update()
{
    std::lock_guard<std::mutex> lock(ifaces_mutex_);
    get_if_addresses();
    if (_opt_nftables)
        tell_nftables();
    if (_opt_proxy)
        tell_proxy();
    if (_opt_monitor)
        print();
}

void ipmon::reload()
{
    std::lock_guard<std::mutex> lock(ifaces_mutex_);
    get_if_addresses();
    if (_opt_nftables)
        tell_nftables();
    if (_opt_monitor)
        print();
}

void ipmon::print()
{
    for (auto p = _ifaces.begin(); p != _ifaces.end(); p++) {
        std::cout << "Interface: " << p->first << " IPv4: ";
        for (auto& vec : p->second->ipv4)
            std::cout <<  vec << " ";
        std::cout << "IPv4_networks: ";
        for (auto& vec : p->second->ipv4_net)
            std::cout <<  vec << " ";
        std::cout << "IPv6: ";
        for (auto& vec : p->second->ipv6)
            std::cout <<  vec << " ";
        std::cout << std::endl;
    }
}

void ipmon::run()
{
    // Create netlink socket for monitoring network interface changes
    _netlink_fd = FileDescriptor(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));
    while (!_netlink_fd.is_valid()) {
        log_and_aleep("Failed to create netlink socket: ");
        std::this_thread::sleep_for(std::chrono::microseconds(250'000));
        _netlink_fd = FileDescriptor(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));
    }

    // Set up netlink message buffer and IO vector
    char buf[16384];
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    // Configure local netlink socket address
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    // Subscribe to IPv4 and IPv6 address notifications
    local.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    local.nl_pid = getpid();

    // Set up message header structure
    struct msghdr msg =
    {
        msg.msg_name = &local,
        msg.msg_namelen = sizeof(local),
        msg.msg_iov = &iov,
        msg.msg_iovlen = 1,
        msg.msg_control = nullptr,
        msg.msg_controllen = 0,
        msg.msg_flags = 0,
    };

    // Bind the netlink socket
    while (bind(_netlink_fd.get(), reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0) {
        log_and_aleep("Failed to bind netlink socket.");
    }

    // Timer state to coalesce rapid network changes
    struct TimerState {
        std::mutex mutex;
        bool ticking{false};
        std::chrono::steady_clock::time_point delay;
    };
    
    TimerState timer;
    
    // Main event loop
    while (true) {
        // Check if we need to process pending updates
        {
            std::lock_guard<std::mutex> lock(timer.mutex);
            if (timer.ticking) {
                auto now = std::chrono::steady_clock::now();
                if (now >= timer.delay) {
                    update();
                    timer.ticking = false;
                }
            }
        }
        
        // Try to receive netlink messages
        ssize_t status = recvmsg(_netlink_fd.get(), &msg, MSG_DONTWAIT);
        if (status < 0) {
            // Handle non-blocking socket timeouts
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::microseconds(250'000));
                continue;
            }
            log_and_aleep("Error: netlink receive error: ");
            continue;
        } else if (status == 0) {
            // Socket was closed
            log_and_aleep("Error: EOF on netlink.");
            continue;
        } else if (msg.msg_namelen != sizeof(local)) {
            // Invalid sender address
            log_and_aleep("Error: Invalid netlink sender address length = " + std::to_string(msg.msg_namelen));
            continue;
        } else {
            // Process received message and start update timer if needed
            if (_opt_monitor)
                    parse_netlink_msg(status, reinterpret_cast<struct nlmsghdr*>(buf));
            if (!timer.ticking) {
                std::lock_guard<std::mutex> lock(timer.mutex);
                timer.delay = std::chrono::steady_clock::now() + _delay;
                timer.ticking = true;
            }
        }
        // Brief sleep to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ipmon::parse_netlink_msg(ssize_t status, struct nlmsghdr* buf)
{
    struct nlmsghdr *h;
    for (h = buf; status >= static_cast<ssize_t>(sizeof(*h)); ) {
        int len = h->nlmsg_len;
        int l = len - sizeof(*h);
        if ((l < 0) || (len > status)) {
            std::cerr << "Error: Invalid message length: " << len << std::endl;
            break;
        }
        struct ifaddrmsg *ifa;
        struct rtattr *tba[IFA_MAX+1];
        ifa = static_cast<struct ifaddrmsg*>(NLMSG_DATA(h));
        auto rta = IFA_RTA(ifa);
        memset(tba, 0, sizeof(struct rtattr *) * (IFA_MAX + 1));
        while (RTA_OK(rta, h->nlmsg_len)) {
            if (rta->rta_type <= IFA_MAX) {
                tba[rta->rta_type] = rta;
            }
            rta = RTA_NEXT(rta,h->nlmsg_len);
        }
        char if_addr[256];
        char if_name[IFNAMSIZ];
        if (ifa->ifa_index == 0 || if_indextoname(ifa->ifa_index, if_name) == nullptr) {
            std::cerr << "Error: No interface name." << std::endl;
            status -= NLMSG_ALIGN(len);
            h = reinterpret_cast<struct nlmsghdr *>(reinterpret_cast<char *>(h) + NLMSG_ALIGN(len));
            continue;
        }
        if (ifa->ifa_family == AF_INET) {
            if (!tba[IFA_ADDRESS]) {
                if (!tba[IFA_LOCAL]) {
                    std::cerr << "Error: No address obtained for interface " << if_name << std:: endl;
                    status -= NLMSG_ALIGN(len);
                    h = reinterpret_cast<struct nlmsghdr *>(reinterpret_cast<char *>(h) + NLMSG_ALIGN(len));
                    continue;
                }
                inet_ntop(AF_INET, RTA_DATA(tba[IFA_LOCAL]), if_addr, sizeof(if_addr));
            }
            inet_ntop(AF_INET, RTA_DATA(tba[IFA_ADDRESS]), if_addr, sizeof(if_addr));
        } else {            // AF_INET6
            if (!tba[IFA_ADDRESS]) {
                std::cerr << "Error: No address obtained for interface " << if_name << std::endl;
                status -= NLMSG_ALIGN(len);
                h = reinterpret_cast<struct nlmsghdr *>(reinterpret_cast<char *>(h) + NLMSG_ALIGN(len));
                continue;
            }
            inet_ntop(AF_INET6, RTA_DATA(tba[IFA_ADDRESS]), if_addr, sizeof(if_addr));
        }
        switch (h->nlmsg_type) {
            case RTM_NEWADDR:
                std::cout << "[NETLINK]: New address assigned to interface "
                                << if_name << ": " << if_addr << std:: endl;
                break;
            case RTM_DELADDR:
                std::cout << "[NETLINK]: Address was removed from interface "
                                << if_name << ": " << if_addr << std:: endl;
                break;
        }
        status -= NLMSG_ALIGN(len);
        h = reinterpret_cast<struct nlmsghdr *>(reinterpret_cast<char *>(h) + NLMSG_ALIGN(len));
    }
}

std::string network_addr_str(in_addr_t addr, in_addr_t mask)
{
    char netAddrBuffer[INET_ADDRSTRLEN];
    auto addr_and_mask = addr & mask;
    inet_ntop(
        AF_INET,
        &addr_and_mask,
        netAddrBuffer,
        INET_ADDRSTRLEN);
    unsigned int count = 0;
    while (mask) {
        count += mask & 1;
        mask >>= 1;
    }
    return std::string(netAddrBuffer) + "/" + std::to_string(count);
}

void ipmon::get_if_addresses()
{
    ifaddrs* raw_ptr = nullptr;
    if (getifaddrs(&raw_ptr) != 0) {
        throw std::runtime_error("getifaddrs failed: " + std::string(strerror(errno)));
    }
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interface_list_ptr(raw_ptr, freeifaddrs);

    std::unordered_map<std::string, std::shared_ptr<struct addrs>> temp_ifaces;
    std::vector<std::string> tmp_ifaces{};

    for (auto ifa = interface_list_ptr.get(); ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name) {
            tmp_ifaces.emplace_back(ifa->ifa_name);
        }
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto binary_addr_ptr = &reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr)->sin_addr;
            auto binary_mask_ptr = &reinterpret_cast<struct sockaddr_in *>(ifa->ifa_netmask)->sin_addr;
            auto net_addr_s = network_addr_str(binary_addr_ptr->s_addr, binary_mask_ptr->s_addr);
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, binary_addr_ptr, addressBuffer, INET_ADDRSTRLEN);
            if (auto find_it = temp_ifaces.find(ifa->ifa_name); find_it != temp_ifaces.end()) {
                find_it->second->ipv4.emplace_back(std::string(addressBuffer));
                auto& nets = find_it->second->ipv4_net;
                if (std::find(nets.begin(), nets.end(), net_addr_s) == nets.end())
                    nets.emplace_back(net_addr_s);
            } else {
                struct addrs new_addrs = { {std::string(addressBuffer)}, {}, {net_addr_s}, {} };
                temp_ifaces.emplace(std::make_pair(std::string(ifa->ifa_name),
                    std::make_shared<struct addrs>(new_addrs)));
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            auto binary_addr_ptr = &reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, binary_addr_ptr, addressBuffer, INET6_ADDRSTRLEN);
            if (auto find_it = temp_ifaces.find(ifa->ifa_name); find_it != temp_ifaces.end()) {
                find_it->second->ipv6.emplace_back(std::string(addressBuffer));
            } else {
                struct addrs new_addrs = { {}, {std::string(addressBuffer)}, {}, {} };
                temp_ifaces.emplace(std::make_pair(std::string(ifa->ifa_name),
                    std::make_shared<struct addrs>(new_addrs)));
            }
        }
    }

    // Add null addresses for interfaces without IPs
    for (auto& tmp : tmp_ifaces) {
        if (temp_ifaces.find(tmp) == temp_ifaces.end()) {
            struct addrs empty_addrs = { {"0.0.0.0"}, {"::"}, {"0.0.0.0"}, {"::"} };
            temp_ifaces.emplace(std::make_pair(std::string(tmp), 
                std::make_shared<struct addrs>(empty_addrs)));
        }
    }

    {
        std::lock_guard<std::mutex> lock(ifaces_mutex_);
        _ifaces = std::move(temp_ifaces);
    }
}

/* Has to be an object value {} */
std::optional<Json::Value> json_from_str(const std::string& str)
{
    Json::CharReaderBuilder builder;
    builder["failIfExtra"] = true;
    std::unique_ptr<Json::CharReader> char_reader(builder.newCharReader());
    std::string error;
    Json::Value row_object;
    const auto str_len = str.length();
    auto first_paren = str.find_first_of('{');
    auto str_c_rec = str.c_str();
    auto ret = char_reader->parse(str_c_rec + first_paren, str_c_rec + str_len, &row_object, &error);

    if (ret) {
        std::cout << "--Read " << str << " GOOD" << std::endl;
    } else {
        std::cout << "--Read " << str << " FAILED" << std::endl;
    }

    if (!ret || first_paren == std::string::npos)
    {
        std::cerr << "json_from_str(str): Failed to parse str=|" << str << "| error=" << error << std::endl;
        return std::nullopt;
    }
    return row_object;
}

Json::Value proxy_fun_setvar(const std::string& var_name, const Json::Value& addrs)
{
    if (!addrs.isArray()) {
        std::cerr << "Proxy fun set_variable requires an argument of type array." << std::endl;
        exit(EXIT_FAILURE);
    }
    Json::Value fun;
    fun["!fun"] = "set_variable";
    fun["="] = var_name;
    fun["input"] = addrs;
    return fun;
}

Json::Value proxy_ref(const std::string& ref_name)
{
    Json::Value ref;
    ref["!ref"] = ref_name;
    return ref;
}

Json::Value proxy_ifcond(const Json::Value& a, const Json::Value& test, const Json::Value& b)
{
    Json::Value cond;
    cond["a"] = a;
    cond["!test"] = test;
    cond["b"] = b;
    return cond;
}

Json::Value proxy_ifcond_then(const Json::Value& ifcond, const Json::Value& do_if)
{
    Json::Value ifobj;
    ifobj["!if"] = ifcond;
    ifobj["+"] = do_if;
    return ifobj;
}

Json::Value proxy_ifcond_then_else(const Json::Value& ifcond, const Json::Value& do_if, const Json::Value& do_else)
{
    Json::Value ifobj = proxy_ifcond_then(ifcond, do_if);
    ifobj["-"] = do_else;
    return ifobj;
}

bool ipmon::is_iface_loopback(const std::string& ifname)
{
    if (ifname == "lo")
        return true;
    return false;
}

std::string get_hostname()
{
    const long hostname_len = sysconf(_SC_HOST_NAME_MAX) + 1;
    std::string hostname(hostname_len, ' ');
    if (gethostname(&hostname[0], hostname_len) == 0) {
        hostname.resize(hostname.find_first_of('\0'));
        return hostname;
    }
    else std::cerr << "gethostname() failed with error: " << strerror(errno) << std::endl;
    return "";
}

void ipmon::tell_proxy()
{
    proxy_seq root_seq, then_seq;

    Json::Value if_address_all = Json::arrayValue;
    Json::Value if_network_all = Json::arrayValue;

    for (auto p = _ifaces.begin(); p != _ifaces.end(); p++)
    {
        if (is_iface_loopback(p->first)) {
            continue;
        }
        Json::Value if_ipv4_address = Json::arrayValue;
        for (auto &a : p->second->ipv4) {
            if_ipv4_address.append(a);
            if_address_all.append(a);
        }
        Json::Value if_ipv6_address = Json::arrayValue;
        for (auto &a : p->second->ipv6) {
            if_ipv6_address.append(a);
            if_address_all.append(a);
        }
        Json::Value if_ipv4_network = Json::arrayValue;
        for (auto &a : p->second->ipv4_net) {
            if_ipv4_network.append(a);
            if_network_all.append(a);
        }

        then_seq.cmd_append(proxy_fun_setvar(p->first + "_ipv4_address", if_ipv4_address));
        then_seq.cmd_append(proxy_fun_setvar(p->first + "_ipv6_address", if_ipv6_address));
        then_seq.cmd_append(proxy_fun_setvar(p->first + "_ipv4_network", if_ipv4_network));

        Json::Value if_ipv6_network = Json::arrayValue;
        for (auto &a : p->second->ipv6_net) {
            if_ipv6_network.append(a);
        }
        then_seq.cmd_append(proxy_fun_setvar(p->first + "_ipv6_network", if_ipv6_network));
    }
    Json::Value hostname = Json::arrayValue;
    hostname.append(get_hostname());
    then_seq.cmd_append(proxy_fun_setvar("hostname", hostname));
    then_seq.cmd_append(proxy_fun_setvar("all_ipv46_address", if_address_all));
    then_seq.cmd_append(proxy_fun_setvar("all_ipv4_network", if_network_all));
    root_seq.cmd_append(
        proxy_ifcond_then(
            proxy_ifcond(
                proxy_ref("phase"),
                "eq",
                "tcp_session"
            ),
            then_seq.get_json()
        )
    );
    atomic_write(_proxy_outfile, root_seq.get_str());

    if (auto result = system(_cmd_reload_proxy); result != 0) {
        throw std::runtime_error("Failed to reload proxy: " + std::to_string(result));
    }

    if (_opt_monitor)
        std::cout << "--Written file " << _proxy_outfile << std::endl;
}

void ipmon::ifaces_update_nft()
{
    nft_root cmd_json_nft;
    for (auto p = _ifaces.begin(); p != _ifaces.end(); p++)
    {
        std::vector<nft_set> sets;
        std::string set_4a = p->first + "_ipv4_address";
        std::string set_4n = p->first + "_ipv4_network";
        sets.emplace_back("ip", "nat", set_4a, "ipv4_addr", p->second->ipv4);
        sets.emplace_back("inet", "filter", set_4a, "ipv4_addr", p->second->ipv4);
        // Error: Could not resolve hostname: Name or service not known [not affecting current version with --flush]
        //sets.emplace_back("ip", "nat", set_4n, "ipv4_addr", p->second->ipv4_net);
        //sets.emplace_back("inet", "filter", set_4n, "ipv4_addr", p->second->ipv4_net);
        for (auto& ns : sets) {
            cmd_json_nft.cmd_append(ns.cmd_add_set_json());
            cmd_json_nft.cmd_append(ns.cmd_flush_set_json());
            cmd_json_nft.cmd_append(ns.cmd_add_element_json());
            cmd_json_nft.test_cmd_append(ns.cmd_add_empty());
        }
    }
    std::unique_ptr<struct nft_ctx, void (*)(struct nft_ctx*)> nft = { nft_ctx_new(NFT_CTX_DEFAULT), nft_ctx_free };
    nft_ctx_output_set_flags(&*nft, NFT_CTX_OUTPUT_JSON);
    if (!nft) {
        log_and_aleep("Failed to obtain nftables context.");
        return;
    }
    // need to test that set can be added to table (permissions, table exists etc.)
    nft_ctx_set_dry_run(&*nft, true);
    bool cmd_ok = true;
    for (auto& cmd : cmd_json_nft.test_cmds) {
        if (nft_run_cmd_from_buffer(&*nft, cmd.c_str()) != 0)
            cmd_ok = false;
    }
    nft_ctx_set_dry_run(&*nft, false);
    if (cmd_ok)
        if (nft_run_cmd_from_buffer(&*nft, cmd_json_nft.get_pp().c_str()) != 0)
            log_and_aleep("Error running nft command: " + cmd_json_nft.get_pp() + " : ");
    //std::cout << cmd_json_nft.get_pp().c_str() << std::endl;
}

void ipmon::ifaces_filewrite()
{
    static constexpr const char* shebang_nft{"#!/usr/sbin/nft -f\n"};
    std::stringstream filecontent_vars, filecontent_sets;
    filecontent_vars << shebang_nft;
    filecontent_sets << shebang_nft;
    for (auto p = _ifaces.begin(); p != _ifaces.end(); p++)
    {
        // prepare update file with constant definitions (unnamed vars)
        filecontent_vars << "redefine " << p->first << "_ipv4_address  = { ";
        for (auto &addr : p->second->ipv4)
            filecontent_vars << addr << ", ";
        if (p->second->ipv4.empty())
            filecontent_vars << "0.0.0.0";
        filecontent_vars << " }\n";

        // IPv4 network addresses  (unnamed vars)
        filecontent_vars << "redefine " << p->first << "_ipv4_network  = { ";
        for (auto &addr : p->second->ipv4_net)
            filecontent_vars << addr << ", ";
        if (p->second->ipv4_net.empty())
            filecontent_vars << "0.0.0.0";
        filecontent_vars << " }\n";

        // prepare update file with named sets
        filecontent_sets << "set " << p->first << "_ipv4_address { type ipv4_addr; elements = { ";
        for (auto &addr : p->second->ipv4)
            filecontent_sets << addr << ", ";
        if (p->second->ipv4.empty())
            filecontent_sets << "0.0.0.0";
        filecontent_sets << " } }\n";

        // IPv4 network addresses (named sets)
        filecontent_sets << "set " << p->first << "_ipv4_network { type ipv4_addr; elements = { ";
        for (auto &addr : p->second->ipv4_net)
            filecontent_sets << addr << ", ";
        if (p->second->ipv4_net.empty())
            filecontent_sets << "0.0.0.0";
        filecontent_sets << " } }\n";
    }
    auto err = atomic_write(nft_outfile_vars(), filecontent_vars.str());
    if (err == std::nullopt) {
        if (_opt_monitor)
            std::cout << "--Written file " << nft_outfile_vars() << std::endl;
    } else log_and_aleep(*err);

    err = atomic_write(nft_outfile_sets(), filecontent_sets.str());
    if (err == std::nullopt) {
        if (_opt_monitor)
            std::cout << "--Written file " << nft_outfile_sets() << std::endl;
    } else log_and_aleep(*err);
}

void ipmon::tell_nftables()
{
    // Always write up-to-date values into file, no matter if updating running conf or reflushing from file
    ifaces_filewrite();
    if (_opt_flush || _opt_start) {
        std::unique_ptr<struct nft_ctx, void (*)(struct nft_ctx*)> nft = { nft_ctx_new(NFT_CTX_DEFAULT), nft_ctx_free };
        if (!nft) {
            log_and_aleep("Failed to obtain nftables context.");
            return;
        }
        nft_run_cmd_from_filename(&*nft, nft_conf_file());
    } else {
        ifaces_update_nft();
    }
}

void ipmon::rm_nft_sets ()
{
    std::unique_ptr<struct nft_ctx, void (*)(struct nft_ctx*)> nft = { nft_ctx_new(NFT_CTX_DEFAULT), nft_ctx_free };
    if (!nft)
        return;
    for (auto p = _ifaces.begin(); p != _ifaces.end(); p++) {
        nft_run_cmd_from_buffer(&*nft, ("delete set ip nat " + p->first).c_str());
        nft_run_cmd_from_buffer(&*nft, ("delete set inet filter " + p->first).c_str());
    }
}

bool ipmon::socket_action(sockserver_cmd action)
{
    FileDescriptor client_socket(socket(AF_UNIX, SOCK_DGRAM, 0));
    if (!client_socket.is_valid()) {
        log_and_aleep("SOCKET ERROR: ");
        return false;
    }
    const auto& cmd = sockserver_cmds.at(action);
    if (sendto(client_socket.get(), cmd, strlen(cmd), 0, socket_server_addr_p(), sizeof(socket_server_addr())) == -1) {
        log_and_aleep("Temporary socket(socket_action) error on sendto(): ");
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    try {
        ipmon ipm;
        ipm.process_cmdline(argc, argv);
        ipm.start();
        auto listen_thread = std::thread(&ipmon::listen_socket, &ipm);
        listen_thread.detach();
        ipm.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
