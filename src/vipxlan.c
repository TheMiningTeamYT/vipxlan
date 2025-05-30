#include <argp.h>
#include <regex.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <net/if.h>
#include <stdint.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>
#include <syslog.h>
#include "ipxkern.h"

#define MAX_IFS 128
#define print_to_log_fmt(log, f, args...) ( { if (isDaemon) { \
    syslog(LOG_NOTICE, f, args); \
} else if (log != NULL)  { \
    time_t currentTime = time(NULL); \
    struct tm* local = localtime(&currentTime); \
    fprintf(log, "[%02u:%02u:%02u]: "f, local->tm_hour, local->tm_min, local->tm_sec, args); \
}})

#define print_to_log(log, f) ( { if (isDaemon) { \
    syslog(LOG_NOTICE, f); \
} else if (log != NULL) { \
    time_t currentTime = time(NULL); \
    struct tm* local = localtime(&currentTime); \
    fprintf(log, "[%02u:%02u:%02u] "f, local->tm_hour, local->tm_min, local->tm_sec); \
}})

#ifdef NOASSERT
#ifdef assert
#undef assert
#endif
#define assert(x) ()
#endif

const char *argp_program_version = "vipxlan v0.1a";
static char args_doc[] = "IN OUT";
static char doc[] = "VIPXLAN - Create a virtual LAN for all your IPX things!";
static bool isDaemon = false;

struct arguments {
    char *ifaceIn;
    regex_t ifaceOut;
    bool daemon;
    FILE* log;
    char* logFile;
};

struct iface {
    int ifindex;
    IPXNet ipxnet;
    int sock_fd;
    uint8_t flags;
#define flag_present 1
};

/* From net/ipx.h */

struct ipx_address {
	uint32_t  net;
	uint8_t    node[IPX_NODE_LEN]; 
	uint16_t  sock;
};

#define ipx_broadcast_node	"\377\377\377\377\377\377"
#define ipx_this_node           "\0\0\0\0\0\0"

#define IPX_MAX_PPROP_HOPS 8

struct ipxhdr {
	uint16_t			ipx_checksum __attribute__ ((__packed__));
#define IPX_NO_CHECKSUM	cpu_to_be16(0xFFFF)
	uint16_t			ipx_pktsize __attribute__ ((__packed__));
	uint8_t			ipx_tctrl;
	uint8_t			ipx_type;
#define IPX_TYPE_UNKNOWN	0x00
#define IPX_TYPE_RIP		0x01	/* may also be 0 */
#define IPX_TYPE_SAP		0x04	/* may also be 0 */
#define IPX_TYPE_SPX		0x05	/* SPX protocol */
#define IPX_TYPE_NCP		0x11	/* $lots for docs on this (SPIT) */
#define IPX_TYPE_PPROP		0x14	/* complicated flood fill brdcast */
	struct ipx_address	ipx_dest __attribute__ ((__packed__));
	struct ipx_address	ipx_source __attribute__ ((__packed__));
};

static struct arguments args;
static struct iface ifs[MAX_IFS];
static int numIfs = 0;

static struct argp_option options[] = {
    {"logfile", 'l', "FILE", 0, "Direct log to FILE. Otherwise, log is printed to stdout."},
    {"daemon", 'd', 0, 0, "Run as daemon."},
    { 0 }
};

static error_t argp_parser(int key, char *arg, struct argp_state *state) {
    struct arguments *args = state->input;
    switch (key) {
        case 'l': 
            args->logFile = arg;
            break;
        case 'd' :
            args->daemon = true;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 2) {
                argp_usage(state);
            }
            switch (state->arg_num) {
                case 0:
                    args->ifaceIn = arg;
                    break;
                case 1:
                    return regcomp(&args->ifaceOut, arg, 0);
                    break;
                default:
                    break;
            }
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 2) {
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {
    options,
    argp_parser,
    args_doc,
    doc
};

static int iface_compare(const void* a, const void* b) {
    struct iface *ifaceA = (struct iface*)a;
    struct iface *ifaceB = (struct iface*)b;
    return ifaceA->ifindex - ifaceB->ifindex;
}

static struct iface *find_iface(int ifindex) {
    struct iface toFind;
    toFind.ifindex = ifindex;
    return (struct iface*) bsearch(&toFind, ifs, numIfs, sizeof(struct iface), iface_compare);
    for (int i = 0; i < numIfs; i++) {
        if (ifs[i].ifindex == ifindex) {
            return &ifs[i];
        }
    }
    return NULL;
}

/* Detect interfaces. */
static int find_ipx_iface(IPXNet network, IPXNode node, char *device, int type, void *data) {
    struct arguments *args = data;
    struct iface *curif;
    int ifindex;
    if (!strcmp(args->ifaceIn, device) || !regexec(&args->ifaceOut, device, 0, NULL, 0)) {
        /* If iface detected is one we're supposed to relay for, get it's ifindex.*/
        ifindex = if_nametoindex(device);
        assert(ifindex > 0);
        /* Check if we already know about this one. */
        if ((curif = find_iface(ifindex)) != NULL) {
            curif->flags |= flag_present;
        } else {
            /* Open a socket for listening for broadcasts on this new interface. */
            /* Code partially taken from bcrelay. */
            struct sockaddr_ll sll;
            struct iface newIf;
            struct iface *newIfPtr;
            if (numIfs >= MAX_IFS) {
                print_to_log(args->log, "Out of available interface slots!\n");
                numIfs = MAX_IFS;
                return 0;
            }
            /* Open socket for this iface. */
            newIf.sock_fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPX));
            assert(newIf.sock_fd != -1);
            memset(&sll, 0, sizeof(sll));
            sll.sll_family          = AF_PACKET;
            sll.sll_ifindex         = ifindex;
            sll.sll_protocol        = htons(ETH_P_IPX);
            if (bind(newIf.sock_fd, (struct sockaddr*)&sll, sizeof(sll))) {
                print_to_log_fmt(args->log, "Bind on iface %s failed!\n", device);
                exit(1);
            } else {
                print_to_log_fmt(args->log, "Bind on iface %s (id #%d) successful! IPX Network: %u\n", device, ifindex, network);
            }
            newIf.ipxnet = network;
            newIf.ifindex = ifindex;
            newIf.flags |= flag_present;
            newIfPtr = ifs;
            while (newIfPtr < &ifs[numIfs]) {
                if (newIfPtr->ifindex >= ifindex) {
                    memmove(newIfPtr + 1, newIfPtr, (&ifs[numIfs] - newIfPtr)*sizeof(struct iface));
                    break;
                }
                newIfPtr++;
            }
            *newIfPtr = newIf;
            numIfs++;
        }
    }
    return 0;
}

_Noreturn static void mainloop(struct arguments args) {
    struct timeval wait;
    char broadcast_node[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    wait.tv_sec = 3;
    wait.tv_usec = 0;
    while (true) {
        fd_set sockets;
        int res;
        int highestFD = -1;
        FD_ZERO(&sockets);
        for (int i = 0; i < numIfs; i++) {
            FD_SET(ifs[i].sock_fd, &sockets);
            if (ifs[i].sock_fd > highestFD) {
                highestFD = ifs[i].sock_fd;
            }
        }
        res = select(highestFD + 1, &sockets, NULL, NULL, &wait);
        if (res < 0) {
            print_to_log_fmt(args.log, "Select failure! Errno: %d\n", errno);
            exit(1);
        } else if (res == 0) {
            /* Check to be sure all our interfaces are still there. */
            for (int i = 0; i < numIfs; i++) {
                ifs[i].flags &= ~flag_present;
            }
            ipx_kern_scan_ifaces(find_ipx_iface, &args);
            for (int i = 0; i < numIfs; i++) {
                if (!(ifs[i].flags & flag_present) && ifs[i].ifindex != -1) {
                    if (ifs[i].sock_fd != -1) {
                        close(ifs[i].sock_fd);
                    }
                    print_to_log_fmt(args.log, "Released device with id #%i.\n", ifs[i].ifindex);
                    memmove(&ifs[i], &ifs[i + 1], (--numIfs - i)*sizeof(struct iface));
                    i--;
                }
            }
            wait.tv_sec = 3;
            wait.tv_usec = 0;
        } else {
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family          = AF_PACKET;
            sll.sll_protocol        = htons(ETH_P_IPX);
            for (int i = 0; i < numIfs; i++) {
                if (FD_ISSET(ifs[i].sock_fd, &sockets)) {
                    char buf[1500];
                    bool broadcast = false;
                    #define header ((struct ipxhdr*)buf)
                    read(ifs[i].sock_fd, buf, sizeof(buf));
                    /* Only route packets going to the same network: we let the kernel handle routing between networks.*/
                    if (header->ipx_type == IPX_TYPE_RIP || header->ipx_type == IPX_TYPE_SAP || ifs[i].ipxnet != ntohl(header->ipx_dest.net)) {
                        continue;
                    }
                    /* Magic number taken from bcrelay*/
                    sll.sll_halen = 6;
                    if (broadcast = !memcmp(header->ipx_dest.node, broadcast_node, sizeof(broadcast_node))) {
                        /* Set the outgoing hardware address to 1's.  True Broadcast */
                        sll.sll_addr[0] = sll.sll_addr[1] = sll.sll_addr[2] = sll.sll_addr[3] = 0xff;
                        sll.sll_addr[4] = sll.sll_addr[5] = sll.sll_addr[6] = sll.sll_addr[7] = 0xff;
                    }
                    for (int j = 0; j < numIfs; j++) {
                        if (j == i) {
                            continue;
                        }
                        
                        /* Relay the packet. */
                        header->ipx_dest.net = htonl(ifs[j].ipxnet);
                        sll.sll_ifindex         = ifs[j].ifindex;
                        /* Code partially taken from bcrelay. */
                        if (broadcast) {
                            res = sendto(ifs[j].sock_fd, buf, ntohs(header->ipx_pktsize), MSG_DONTWAIT|MSG_DONTROUTE,
                            (struct sockaddr*)&sll, sizeof(sll));
                        } else {
                            memcpy(sll.sll_addr, header->ipx_dest.node, 6);
                            res = sendto(ifs[j].sock_fd, buf, ntohs(header->ipx_pktsize), MSG_DONTWAIT|MSG_DONTROUTE,
                            (struct sockaddr*)&sll, sizeof(sll));
                        }
                        
                        if ((res = sendto(ifs[j].sock_fd, buf, ntohs(header->ipx_pktsize), MSG_DONTWAIT|MSG_DONTROUTE,
                            (struct sockaddr*)&sll, sizeof(sll))) < 0) {
                            /* Rather than figure out for myself what these mean, I just took the code from bcrelay. */
                            if (errno == ENETDOWN) {
                                print_to_log(args.log, "ignored ENETDOWN from sendto(), a network interface was going down?\n");
                                close(ifs[j].sock_fd);
                                print_to_log_fmt(args.log, "Released device with index %i.\n", ifs[i].ifindex);
                                memmove(&ifs[j], &ifs[j + 1], (--numIfs - j)*sizeof(struct iface));
                                if (i > j--) {
                                    i--;
                                }
                            } else if (errno == ENXIO) {
                                print_to_log(args.log, "ignored ENETDOWN from sendto(), a network interface was going down?\n");
                            } else if (errno == ENOBUFS) {
                                print_to_log(args.log, "ignored ENOBUFS from sendto(), temporary shortage of buffer memory\n");
                            } else if (errno == EMSGSIZE) {
                                print_to_log_fmt(args.log, "mainloop: Error, sendto failed! Message too large! Size: %s\n", ntohs(header->ipx_pktsize));
                                exit(1);
                            } else {
                                print_to_log_fmt(args.log, "mainloop: Error, sendto failed! (rv=%d, errno=%d)\n", res, errno);
                                exit(1);
                            }
                        }
                    }
                }
            }
        }
    }
}

static void sigHandler(int sig) {
    if (args.log != NULL) {
        fputs("\n", args.log);
        fclose(args.log);
        args.log = NULL;
    }
    if (sig == SIGINT || sig == SIGTERM || sig == SIGABRT) {
        /* Clean up interfaces. */
        for (int i = 0; i < numIfs; i++) {
            close(ifs[i].sock_fd);
        }
    }
    exit(sig);
}

static void daemonize() {
    /* Code taken from: https://github.com/pasce/daemon-skeleton-linux-c */
    pid_t pid;
    
    /* Fork off the parent process */
    pid = fork();
    
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);
    
     /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);
    
    /* Catch, ignore and handle signals */
    /*TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    /* Fork off for the second time*/
    pid = fork();
    
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);
    
    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    /* Set new file permissions */
    umask(0);
    
    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");
    
    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--) {
        close(x);
    }
    
    /* Open the log file */
    openlog("vipxland", LOG_PID, LOG_DAEMON);
}

int main(int argc, char** argv) {
    args.log = NULL;
    args.logFile = NULL;
    args.daemon = false;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    if (args.daemon) {
        daemonize();
        isDaemon = true;
    } else {
        if (args.logFile == NULL) {
            args.log = stdout;
        } else if ((args.log = fopen(args.logFile, "a")) == NULL) {
            printf("Unable to open log file %s!\n", args.logFile);
            exit(1);
        } else {
            time_t currentTime = time(NULL);
            struct tm* local = localtime(&currentTime);
            fprintf(args.log, "--- VIPXLAN Start log %d/%02d/%02d %u:%u:%u ---\n\n", local->tm_year + 1900, local->tm_mon + 1, local->tm_mday, 
                local->tm_hour, local->tm_min, local->tm_sec);
        }
    }
    ipx_kern_scan_ifaces(find_ipx_iface, &args);
    signal(SIGINT, sigHandler);
    signal(SIGABRT, sigHandler);
    signal(SIGSEGV, sigHandler);
    signal(SIGTERM, sigHandler);
    signal(SIGKILL, sigHandler);
    signal(SIGILL, sigHandler);
    signal(SIGBUS, sigHandler);
    signal(SIGQUIT, sigHandler);
    mainloop(args);
}