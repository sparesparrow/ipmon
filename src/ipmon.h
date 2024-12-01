/*! \file
 * \brief ipmon
 */
#include <vector>
#include <iostream>
#include <unordered_map>
#include <memory>
#include <jsoncpp/json/json.h>
#include <sstream>
#include <sys/un.h>
#include <sys/socket.h>
#include <thread>
#include <map>
#include <mutex>
#include <string>
#include "FileDescriptor.h"
#include "SocketGuard.h"

// TODO: Split header files

/*! Holds data for network interfaces and addresses */
struct addrs
{
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    std::vector<std::string> ipv4_net;
    std::vector<std::string> ipv6_net;
};

/*! The ipmon, of which only one instance should exist.
 *  Maybe will be transformed to singleton.
 */
class ipmon
{
public:
    enum class sockserver_cmd
    {
        update,
        reload,
        _size
    };
    const std::map<sockserver_cmd, const char*> sockserver_cmds
    {
        { sockserver_cmd::update, "update" },
        { sockserver_cmd::reload, "reload" },
    };
    //! Constructs the object
    ipmon();
    //! Destructs the object
    ~ipmon();
    //! Prints a help message.
    void help();
    /*! Processes the cmdline arguments.
     * \param[in] argc from main()
     * \param[in] argv from main()*/
    void process_cmdline(int argc, char* argv[]);
    /*! Calls \c update() immediately if \c _opt_start is set. Should be called before \c run() */
    void start()
    {
        if (_opt_start)
        {
            update();
            _opt_start = false;
        }
    }
    /*! Starts monitoring netlink socket for address related messages. Upon message arrival,
     *  a timer with duration of \c _delay is set. After that time message is processed.
     *  Reading from socket continues, and if \c _opt_monitor is set, every message is parsed by \c parse_netlink_msg()
     *  Timer is reset in SIGALRM handling function \c update() */
    void run();
    /*! Prints information about network interfaces and addresses */
    void print();
    /*! \return get path to listening socket \c _socket_server_path */
    const auto& socket_server_path() { return _socket_server_path; }
    /*! \return get \c _socket_server_addr as a struct \ref sockaddr_un  */
    struct sockaddr_un& socket_server_addr() { return _socket_server_addr; }
    /*! \return get \c _socket_server_addr as a pointer to \ref sockaddr  */
    struct sockaddr* socket_server_addr_p() { return reinterpret_cast<struct sockaddr*>(&_socket_server_addr); }
    /*! \return whether the socket initialization at  \c _socket_server_path was successful or not.*/
    bool init_socket();
    /*! Unix socket server listening on \c _socket_server_path accepting requests defined in \c sockserver_cmds */
    void listen_socket();
    /*! Sends a message to unix domain socket listening on \ref _socket_server_addr.
     * \param[in] action message for the server
     * \return true on success, false otherwise */
    bool socket_action(sockserver_cmd action);
    /*! \param[in] ifname queried interface name
     *  \return whether the interface is loopback or not.*/
    bool is_iface_loopback(const std::string& ifname);
private:
    struct sockaddr_un _socket_server_addr;
    //! Stored interface names and addresses
    std::unordered_map<std::string, std::shared_ptr<struct addrs>> _ifaces;
    //! Whether to serve nftables
    bool _opt_nftables = false;
    //! Whether to serve proxy
    bool _opt_proxy = false;
    //! Whether to flush and reload nftables configuration upon any address of any device had changed
    bool _opt_flush = false;
    //! Whether parse netlink messages and write various information to stdout
    bool _opt_monitor = false;
    //! Whether to update interface information on program start
    bool _opt_start = false;
    //! Time for which related messages should be ignored
    std::chrono::microseconds _delay {200'000};
    //! Unix socket server path
    static constexpr const char* _socket_server_path = "/run/ipmon.sock";
    //! Proxy persistent configuration file
    std::string _proxy_outfile{"/etc/ipmon/ifacesAddrs.json"};
    //! Command to reload proxy service
    static constexpr const char* _cmd_reload_proxy = "systemctl reload proxy --quiet";
    //! Nftables persistent configuration file
    std::string _nft_outfile{"/etc/impon/ifacesAddrs"};
    //! Nftables persistent configuration file sets
    std::string nft_outfile_sets() const { return _nft_outfile + ".sets"; }
    //! Nftables persistent configuration file variables
    std::string nft_outfile_vars() const { return _nft_outfile + ".vars"; }
    //! Nftables configuration file for ipmon-handled rules
    static constexpr const char* _nft_conf_ipmon = "/etc/impon/nftables.conf";
    //! Nftables configuration file for default rules
    static constexpr const char* _nft_conf_default = "/etc/nftables.conf";
    //! Command to check if ipmon-handled rules are included in nftables
    static constexpr const char* _cmd_nftables_status = "nft list ruleset | grep -q 'include \"/etc/ipmon/nftables.conf\"'";
    /*! \return path to which nftables configuration should be used for reloading the configuration. */
    auto nft_conf_file() {
        int ret = system(_cmd_nftables_status);
        return (WEXITSTATUS(ret) == 0 ? _nft_conf_ipmon : _nft_conf_default);
    }
    /*! Called from \c start() and after receiving IPv4/IPv6 address-related message from netlink.
     *  Obtains current interface information and updates served components. */
    void update();
    /*! Action performed based on \c sockserver_cmd::reload command coming from outside.
     *  Obtains current interface information and updates served components. Reloads the whole nft configuration */
    void reload();
    /*! Updates nftables configuration and configuration file with information in \c _ifaces
     *  Running configuration is updated by reseting named set values (accesed with @set)
     *  Persistent configuration is updated by overwriting file at \c nft_outfile_sets() and \c nft_outfile_vars()
     *  where values are put into variables (accesed with $variable) or sets (accesed with @set).
     *  Persistent configuration is reloaded on program start if \c _opt_start is set and if \c _opt_flush is set then
     *  it is reloaded every time netlink received an address related message.
     */
    void tell_nftables();
    /*! Updates proxy configuration file at \c _proxy_outfile with addrs in \c _ifaces and reloads proxy service.*/
    void tell_proxy();
    /*! Called from \c run() to parse netlink message for various information
     * \param[in] status message status
     * \param[in] buf message itself */
    void parse_netlink_msg(ssize_t status, struct nlmsghdr* buf);
    /*! Obtains information about network interfaces using getifaddrs()
     *  Interfaces with no IP addresses assigned will have 0.0.0.0 and ::
     *  Resets value of \c _ifaces */
    void get_if_addresses();
    /*! Removes named sets from nftables for every interface in \c _ifaces (not very useful)*/
    void rm_nft_sets();
    /*! Updates nftables IP addresses files \ref nft_outfile_sets() and \ref nft_outfile_vars */
    void ifaces_filewrite();
    /*! Updates nftables runtime configuration */
    void ifaces_update_nft();

    // RAII wrapper for file descriptors
    FileDescriptor _socket_server_fd;
    FileDescriptor _netlink_fd;

    // Mutex for thread safety
    std::mutex ifaces_mutex_;

    // Using SocketGuard for Unix domain sockets
    SocketGuard _socket_guard;
};
/*! Base class for json data structure. */

class cmd_json
{
public:
    //! Constructs the object
    cmd_json(std::string keyroot): _keyroot(keyroot) { }
    //! Destructs the object
    virtual ~cmd_json() {}
    /*! \return stored value as a string */
    const std::string get_str()
    {
        Json::Value root;
        root[_keyroot] = *_proot;
        Json::FastWriter writer;
        return writer.write(root);
    }
    /*! \return stored value as a pretty-print string */
    const std::string get_pp()
    {
        Json::Value root;
        root[_keyroot] = *_proot;
        return root.toStyledString();
    }
    /*! \return stored value as JSON object/array */
    const Json::Value get_json()
    {
        Json::Value root;
        root[_keyroot] = *_proot;
        return root;
    }
protected:
    //! Stored commands
    std::shared_ptr<Json::Value> _proot;
private:
    std::string _keyroot;
};

/*! Base class for JSON array data structure. */
class cmd_json_a : public cmd_json
{
public:
    //! Constructs the object
    cmd_json_a(std::string keyroot): cmd_json(keyroot)
    {
        _proot = std::make_shared<Json::Value>(Json::Value(Json::arrayValue));
    }
    //! Destructs the object
    virtual ~cmd_json_a() {}
    //! Adds command to the commands list
    void cmd_append(Json::Value cmd)
    {
        _proot->append(cmd);
    }
protected:
private:
};

class proxy_seq : public cmd_json_a
{
public:
    //! Constructs the object
    proxy_seq(): cmd_json_a("!seq") { }
};

/*! Base class for nftables commands */
class nft_root : public cmd_json_a
{
public:
    //! Constructs the object
    nft_root(): cmd_json_a("nftables") { }
    //! Destructs the object
    virtual ~nft_root() {}
    //! Adds testing command to dry run before running actual command
    void test_cmd_append(std::string cmd)
    {
        test_cmds.emplace_back(cmd);
    }
    //! Stored testing commands
    std::vector<std::string> test_cmds{};
};

/*! Holds data for creating various \c nft commands */
class nft_set : public nft_root
{
public:
    //! Constructs the object from given parameters
    nft_set(std::string family,
            std::string table,
            std::string name,
            std::string type,
            std::vector<std::string>& addresses): nft_root(),
        _family(family), _table(table), _name(name), _type(type), _addresses(addresses)  { }
    //! \return JSON command creating an empty set
    Json::Value cmd_add_set_json(bool append = false)
    {
        Json::Value set;
        set["family"] = _family;
        set["table"] = _table;
        set["name"] = _name;
        set["type"] = _type;
        Json::Value set_root;
        set_root["set"] = set;
        Json::Value add;
        add["add"] = set_root;
        if (append)
            _proot->append(add);
        return add;
    }
    //! \return JSON command flushing a set. Prints some errors if set does not exist
    Json::Value cmd_flush_set_json(bool append = false)
    {
        Json::Value set;
        set["family"] = _family;
        set["table"] = _table;
        set["name"] = _name;
        Json::Value set_root;
        set_root["set"] = set;
        Json::Value flush;
        flush["flush"] = set_root;
        if (append)
            _proot->append(flush);
        return flush;
    }
    //! \return JSON command filling the set with elements or creating such set if not exists
    Json::Value cmd_add_element_json(bool append = false)
    {
        Json::Value element;
        element["family"] = _family;
        element["table"] = _table;
        element["name"] = _name;
        Json::Value ele = Json::arrayValue;
        for (auto &a : _addresses)
            ele.append(a);
        if (ele.empty())
            ele.append("0.0.0.0");
        element["elem"] = ele;
        Json::Value element_root;
        element_root["element"] = element;
        Json::Value add;
        add["add"] = element_root;
        if (append)
            _proot->append(add);
        return add;
    }
    //! \return BISON command creating an empty set
    const std::string cmd_add_empty()
    {
        std::stringstream ss;
        ss << "add set " << _family << " " << _table << " " << _name << " { type " << _type << " ; }";
        return ss.str();
    }
    //! \return BISON command flushing a set. Prints some errors if set does not exist
    const std::string cmd_flush()
    {
        std::stringstream ss;
        ss << "flush set " << _family << " " << _table << " " << _name;
        return ss.str();
    }
    //! \return BISON command filling the set with elements or creating such set if not exists
    const std::string cmd_add()
    {
        std::stringstream ss;
        ss << "add set " << _family << " " << _table << " " << _name << " { type " << _type << " ; elements = { ";
        for (auto &a : _addresses)
            ss << a << ", ";
        ss << "} ; }";
        return ss.str();
    }
private:
    //! Address family (contains \c table )
    std::string _family;
    //! Table (contains set \c name )
    std::string _table;
    //! Set name (must specify \c type )
    std::string _name;
    //! Set type (currently only \c ipv4_addr )
    std::string _type;
    //! Set elements, must not be empty
    std::vector<std::string>& _addresses;
};
