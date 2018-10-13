/*
 * Project: mcscanner - Multicast Network Scanner
 * File name: mcSniff.cpp
 * Description:  This program (mcscanner) scans a network for multicast sources and traffic,
 *   which are explicitly avoided in typical network scanners such as nmap.
 *   The program sends PIM Hello and IGMP Queries, then listens for a specified
 *   amount of time.  It then prints the source and destination of each message and
 *   related information for the particular multicast address.  The multicast address
 *   range information is taken from: http://www.iana.org/assignments/multicast-addresses/.
 *
 * Author: Vince Gibson, Georgia Tech Research Institute
 * Copyright: Georgia Tech Research Corporation, Copyright (C) 2010
 *
 * @see The GNU Public License (GPL)
 */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <stdio.h>
#include <string.h>
//#include <stdbool.h>
#include <stdlib.h>
//#include <ctype.h>
//#include <errno.h>
#include <netdb.h>
#include <unistd.h>
//#include <string.h>
//#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
//#include <netinet/in.h>
//#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <time.h>
#include <set>
#include <signal.h>
#include <semaphore.h>
#include <stdlib.h>

#include "mcLookupTable.h"
#include "gtkMcScanner.h"

using namespace std;

#define SIZE_ETHERNET 14

// set this to 1 if the multicast address table gets updated
#define CHECK_LUT 0

extern TreeItem gTempMcListIGMP[100];
extern TreeItem gTempMcList[100];
extern void addTreeData();
extern sem_t gDisplayLock;
sem_t gPcapLock;

/////////////////////////////////////////////////////////////////////
pcap_t *pcapHandle;
timer_t timerid;

/////////////////////////////////////////////////////////////////////

time_t mcHoldTime = 3;
time_t mcEndTime = 0;
bool displayIANA = true;
bool continuousMode = false;
long int numLUT=0;

int gIgmpCount = 0;
int gOthersCount = 0;

// multicast address item
class multicast
{
public:
    in_addr srcAddr;
    in_addr dstAddr;
    u_short sPort;
    u_short dPort;
    mutable bool duplicate;
    multicast(in_addr src, u_short sport, in_addr dst, u_short dport)
    {
        srcAddr = src;
        sPort = sport;
        dstAddr = dst;
        dPort = dport;
        duplicate = false;
    }
};

// used to ignore duplicates
class mcCompare
{
public:
    bool operator()(multicast ml, multicast mr)
    {
        if (ml.dstAddr.s_addr == mr.dstAddr.s_addr )
        {
            if (ml.dPort == mr.dPort )
            {
                if (ml.srcAddr.s_addr < mr.srcAddr.s_addr )
                    return true;
                else
                    return false;
            }
            else
            {
                if (ml.dPort < mr.dPort )
                    return true;
                else
                    return false;
            }
        }
        else if (ml.dstAddr.s_addr < mr.dstAddr.s_addr )
            return true;
        else
            return false;
    }
};

set <multicast, mcCompare> multicastIGMPAddresses;
set <multicast, mcCompare> multicastAddresses;

char pcapErrBuf[PCAP_ERRBUF_SIZE];

/*
//
// NOTE: The following pcap code was taken from various examples on the Internet.
//
*/

struct sniff_ethernet
{
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip
{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

/*
//
// end pcap code
//
*/

#define REMOTE_SERVER_PORT 13820
#define MAX_MSG 100

enum {MSG_TYPE_PIM_HELLO};

struct PIM_Header
{
int type     :
    4;
int version  :
    4;
int reserved :
    8;
int checksum :
    16;
};

#pragma pack(2)
struct PIM_Option_Hold
{
int type :
    16;
int length :
    16;
int value :
    16;
};

struct PIM_Option_GenerationID
{
int type :
    16;
int length :
    16;
long int value :
    32;
};

struct PIM_Hello
{
    struct PIM_Header header;
    struct PIM_Option_Hold hold;
    struct PIM_Option_GenerationID generationID;
    //long int holdtime : 48;
    //long int DR_Priority  : 64;
};

struct IGMP_Query_v2
{
int type     :
    8;
int maxResponseTime  :
    8;
int checksum :
    16;
long int multicastAddress :
    32;
};

struct IGMP_Query_v3
{
int type     :
    8;
int maxResponseTime  :
    8;
int checksum :
    16;
long int multicastAddress :
    32;
int QRV     :
    8;
int QQIC     :
    8;
int NumSrc     :
    16;
};

long int lookupMulticastDestination(in_addr_t dst)
{
    // lookup multicast destination
    for (int i=0; i<numLUT; i++)
    {
        if ((multicastAddressLUT[i].startAddr >= dst) && (multicastAddressLUT[i].endAddr <= dst))
        {
            return i;
        }
    }
    return -1;
}

// check for destinations that have multiple sources which may indicate multicast injection attack
// no duplicate pairs are added to the list, so we just need to check for the same destination
// note: with set iterators, can't compare the index, so we check the src as well
void checkForDupes()
{
    set<multicast>::iterator i;
    set<multicast>::iterator j;
    // for each destination in the list, check all gTempMcList
    for (i = multicastAddresses.begin(); i != multicastAddresses.end(); i++)
    {
        for (j = multicastAddresses.begin(); j != multicastAddresses.end(); j++)
        {
            if((i->dstAddr.s_addr == j->dstAddr.s_addr) && (i->srcAddr.s_addr != j->srcAddr.s_addr))
            {
                if(i->dPort == j->dPort)
                {
                    i->duplicate = true;
                }
            }
        }
    }
}

void printResults()
{
    long int indexLUT;
    set<multicast>::iterator i;
    gIgmpCount = 0;
    gOthersCount = 0;
    char temp[1000];

    for (i = multicastIGMPAddresses.begin(); i != multicastIGMPAddresses.end(); i++)
    {
        strcpy(gTempMcListIGMP[gIgmpCount].source, inet_ntoa(i->srcAddr));
        sprintf(temp,": %u",ntohs(i->sPort));
        strcat(gTempMcListIGMP[gIgmpCount].source, temp);

        strcpy(gTempMcListIGMP[gIgmpCount].destination, inet_ntoa(i->dstAddr));
        sprintf(temp,": %u",ntohs(i->dPort));
        strcat(gTempMcListIGMP[gIgmpCount].destination, temp);

        if(displayIANA)
        {
            indexLUT = lookupMulticastDestination(i->dstAddr.s_addr);
            if (indexLUT != -1)
            {
                strcpy(temp,multicastAddressLUT[indexLUT].description);
                strcat(temp, " ");
                strcat(temp, multicastAddressLUT[indexLUT].reference);
                strcpy(gTempMcListIGMP[gIgmpCount].IANA, temp);
            }
            else
                gTempMcListIGMP[gIgmpCount].IANA[0] = '\0';
        }
        gIgmpCount++;
    }

    for (i = multicastAddresses.begin(); i != multicastAddresses.end(); i++)
    {
        strcpy(gTempMcList[gOthersCount].source, inet_ntoa(i->srcAddr));
        sprintf(temp,": %u",ntohs(i->sPort));
        strcat(gTempMcList[gOthersCount].source, temp);

        strcpy(gTempMcList[gOthersCount].destination, inet_ntoa(i->dstAddr));
        sprintf(temp,": %u",ntohs(i->dPort));
        strcat(gTempMcList[gOthersCount].destination, temp);

        if(displayIANA)
        {
            indexLUT = lookupMulticastDestination(i->dstAddr.s_addr);
            if (indexLUT != -1)
            {
                strcpy(temp,multicastAddressLUT[indexLUT].description);
                strcat(temp, " ");
                strcat(temp, multicastAddressLUT[indexLUT].reference);
                strcpy(gTempMcList[gOthersCount].IANA, temp);
                gTempMcList[gOthersCount].duplicate = 0;
            }
            else
            {
                // only show duplicates if it's NOT an IANA address
                gTempMcList[gOthersCount].duplicate = i->duplicate;
                gTempMcList[gOthersCount].IANA[0] = '\0';
            }
        }
        gOthersCount++;
    }
}

void timerCallback(union sigval  arg)
{
    pcap_breakloop(pcapHandle);
    checkForDupes();

    sem_wait(&gDisplayLock);
    printResults();
    sem_post(&gDisplayLock);

    sem_post(&gPcapLock);

    return;
}

int setTimer (time_t delay)
{
    struct sigevent se;
    struct itimerspec ts;
    struct itimerspec tso;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = &timerid;
    se.sigev_notify_function = timerCallback;
    se.sigev_notify_attributes = NULL;

    if (-1 == timer_create(CLOCK_REALTIME, &se, &timerid))
    {
        perror("timer_create:");
        return(1);
    }

    ts.it_value.tv_sec = delay;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    if (-1 == timer_settime(timerid, 0, &ts, &tso))
    {
        perror("timer_settime:");
        return(1);
    }

    return 0;
}

void printUsage()
{
    printf("Usage: mcscanner [device] [options]\n");
    printf(" device = Ethernet device");
    printf("\nOptions:\n");
    printf("  -?       Prints this screen\n");
    printf("  -t time  Time (s) to listen\n");
    printf("  -q       Doesn't print IANA information\n");
    printf("  -p       Prints the IANA table\n");
    printf("\n");
}

void printLUT()
{
    long int i=0;
    do
    {
        if (!strcmp("END",multicastAddressLUT[i].start))
            break;
        printf("%s - %s -> %s, %s\n",
               multicastAddressLUT[i].start,
               multicastAddressLUT[i].end,
               multicastAddressLUT[i].description,
               multicastAddressLUT[i].reference);
        i++;
    }
    while (1);
}

// Build the multicast addresses and add them to the set
void buildLUT()
{
    numLUT=0;
    do
    {
        if (!strcmp("END",multicastAddressLUT[numLUT].start))
            break;
        multicastAddressLUT[numLUT].startAddr = inet_addr(multicastAddressLUT[numLUT].start);
        multicastAddressLUT[numLUT].endAddr = inet_addr(multicastAddressLUT[numLUT].end);
#if CHECK_LUT == 1
        if (multicastAddressLUT[numLUT].startAddr > multicastAddressLUT[numLUT].endAddr)
            printf("Possible Bad LUT entry: %ld src: %s dst: %s!!!  Please fix.\n",numLUT, multicastAddressLUT[numLUT].start,multicastAddressLUT[numLUT].end);
#endif
        numLUT++;
    }
    while (1);
}

int sendQuery()
{
    int sd, rc;
    struct sockaddr_in cliAddr, remoteServAddr;
    struct hostent *h;

    const char* QUERY_ADDRESS = "224.0.0.1";

    struct IGMP_Query_v2 queryV2;
    struct IGMP_Query_v3 queryV3;
    queryV2.type = 0x11;
    queryV2.maxResponseTime = mcHoldTime;
    queryV2.checksum = 0;
    queryV2.multicastAddress = 0;

    queryV3.type = 0x11;
    queryV3.maxResponseTime = mcHoldTime;
    queryV3.checksum = 0;
    queryV3.multicastAddress = 0;
    queryV3.QRV = 2;
    queryV3.QQIC = 125;
    queryV3.NumSrc = 0;

    // get server IP address
    h = gethostbyname(QUERY_ADDRESS);
    if (h==NULL)
    {
        printf("Unknown host '%s' \n", QUERY_ADDRESS);
        return 1;
    }

    remoteServAddr.sin_family = h->h_addrtype;
    memcpy((char *) &remoteServAddr.sin_addr.s_addr,
           h->h_addr_list[0], h->h_length);
    remoteServAddr.sin_port = htons(REMOTE_SERVER_PORT);

    // create socket
    sd = socket(AF_INET,SOCK_RAW,2);
    if (sd<0)
    {
        printf("Cannot open socket \n");
        return 1;
    }

    // bind any port
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    cliAddr.sin_port = htons(0);

    rc = bind(sd, (struct sockaddr *) &cliAddr, sizeof(cliAddr));
    if (rc<0)
    {
        printf("Cannot bind port\n");
        return 1;
    }

    // send message
    rc = sendto(sd, &queryV2, sizeof(queryV2), 0,
                (struct sockaddr *) &remoteServAddr,
                sizeof(remoteServAddr));

    if (rc<0)
    {
        printf("Cannot send QueryV2 data. Code: %d\n",rc);
        close(sd);
        return 1;
    }

    //printf("Sending Query V3 to '%s'\n", inet_ntoa(*(struct in_addr *)h->h_addr_list[0]));
    rc = sendto(sd, &queryV3, sizeof(queryV3), 0,
                (struct sockaddr *) &remoteServAddr,
                sizeof(remoteServAddr));

    if (rc<0)
    {
        printf("Cannot send QueryV3 data. Code: %d\n",rc);
        close(sd);
        return 1;
    }

    close(sd);
    return 0;
}

int sendPim()
{

    int sd, rc;
    struct sockaddr_in cliAddr, remoteServAddr;
    struct hostent *h;
    struct PIM_Hello PIMHelloMsg;

    // can be random
    const unsigned int GEN_ID = 18330;

    PIMHelloMsg.header.version = 2;
    PIMHelloMsg.header.type = MSG_TYPE_PIM_HELLO;
    PIMHelloMsg.header.reserved = 0;
    PIMHelloMsg.header.checksum = 0;
    PIMHelloMsg.hold.type = htons(1);
    PIMHelloMsg.hold.length = htons(2);
    PIMHelloMsg.hold.value = htons(60);
    PIMHelloMsg.generationID.type = htons(20);
    PIMHelloMsg.generationID.length = htons(4);
    PIMHelloMsg.generationID.value = htons(GEN_ID);
    //PIMHelloMsg.DR_Priority = 1;

    const char* PIM_ADDRESS = "224.0.0.13";

    // get server IP address
    h = gethostbyname(PIM_ADDRESS);
    if (h==NULL)
    {
        printf("Unknown host '%s' \n", PIM_ADDRESS);
        return 1;
    }

    remoteServAddr.sin_family = h->h_addrtype;
    memcpy((char *) &remoteServAddr.sin_addr.s_addr,
           h->h_addr_list[0], h->h_length);
    remoteServAddr.sin_port = htons(REMOTE_SERVER_PORT);

    // create sockett
    sd = socket(AF_INET,SOCK_RAW,103);
    if (sd<0)
    {
        printf("Cannot open socket \n");
        return 1;
    }

    // bind any port
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    cliAddr.sin_port = htons(0);

    rc = bind(sd, (struct sockaddr *) &cliAddr, sizeof(cliAddr));
    if (rc<0)
    {
        printf("Cannot bind port\n");
        return 1;
    }

    // send message
    rc = sendto(sd, &PIMHelloMsg, sizeof(PIMHelloMsg), 0,
                (struct sockaddr *) &remoteServAddr,
                sizeof(remoteServAddr));

    if (rc<0)
    {
        printf("Cannot send PIM message. Code: %d\n",rc);
        close(sd);
        return 1;
    }
    return 0;
}

void pcapCallback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* declare pointers to packet headers */
    //const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;

    int size_ip;
    int size_tcp;

    /* define ethernet header */
    //ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20)
    {
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20)
    {
        //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        //return;
    }

    // if a multicast packet
    unsigned int tmpSrc;
    unsigned int tmpDst;

    tmpSrc = ip->ip_src.s_addr & 0x000000ff;
    tmpDst = ip->ip_dst.s_addr & 0x000000ff;

    if (((tmpSrc >= 0xe0) && (tmpSrc < 0xf0)) ||
            ((tmpDst >= 0xe0) && (tmpDst < 0xf0)))
    {
        // insert multicast, will not insert duplicates
        // determine protocol
        switch (ip->ip_p)
        {
        case IPPROTO_IGMP:
            multicastIGMPAddresses.insert(multicast(ip->ip_src, tcp->th_sport, ip->ip_dst, tcp->th_dport));
            break;
        default:
            multicastAddresses.insert(multicast(ip->ip_src, tcp->th_sport, ip->ip_dst, tcp->th_dport));
            break;
        }
    } // if multicast
}

void changeTime(int time)
{
    mcHoldTime = time;
}

extern "C" int runScan(void)
{
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char *dev = NULL;

    continuousMode = true;

    dev = pcap_lookupdev(pcapErrBuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", pcapErrBuf);
        fprintf(stderr, "Do you have correct privileges? Try sudo.\n");
        return 2;
    }

    if (pcap_lookupnet(dev, &net, &mask, pcapErrBuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    pcapHandle = pcap_open_live(dev, BUFSIZ, 1, 1000, pcapErrBuf);
    if (pcapHandle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, pcapErrBuf);
        fprintf(stderr, "Do you have correct privileges? Try sudo.\n");
        return 2;
    }

    if (pcap_setnonblock(pcapHandle, 1, pcapErrBuf) == -1)
    {
        fprintf(stderr, "Can't setnoblock for pcap: %s\n", dev);
    }

    buildLUT();

    sem_init(&gPcapLock,0,1);


    do
    {
        sem_wait(&gPcapLock);

        mcEndTime = time(NULL) + mcHoldTime;
        multicastIGMPAddresses.clear();
        multicastAddresses.clear();

        // send messages
        int result = sendPim();
        if (result)
            printf("Could not send PIM!\n");
        result = sendQuery();
        if (result)
            printf("Could not send QUERY!\n");

        setTimer(mcHoldTime);

        // listen to traffic
        pcap_loop(pcapHandle,-1,pcapCallback,NULL);

    }
    while (continuousMode);

    pcap_close(pcapHandle);

    sem_destroy(&gPcapLock);

    return (0);
}


