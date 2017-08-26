/**************************************************************************************************
*  File: ahnService.c
*
*  Author: qige
*
*  Description:  This file is used to start AHN socket&mux service.
*
*-------------------------------------------------------------------------------------------------
*  Change History:
*-------------------------------------------------------------------------------------------------
*  Date				Author			Description
*-------------------------------------------------------------------------------------------------
*  2017-07-12       qige            create
*  2017-08-04		qige			init 4 thread: at_read,mux_read,socket_read,socket_raw_read;
*  2017-08-17		qige			finish socket_raw_read & mux_read;
**************************************************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<termios.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>//ether_arp
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#define AT_DEV "/dev/TTYEMS35"
#define MUX_DEV "/dev/lmi2"
#define HEAD_LEN_MUX 9
#define HEAD_LEN_IP_TRANS 2

#define print_log(fmt, ...) \
    printf("[%04d]%s() " fmt, __LINE__, __FUNCTION__, ####__VA_ARGS__)
#define print_err(fmt, ...) \
    printf("[%04d]%s() err: " fmt, __LINE__, __FUNCTION__, ####__VA_ARGS__)

#define xdebug 1
#define xunused __attribute__((unused))

/* 以太网帧首部长度 */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/* 整个arp结构长度 */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/* 以太网 + 整个arp结构长度 */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN

#define IP_ADDR_LEN   4
//广播地址
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define HDR_LEN_ETH  sizeof(struct ether_header)
#define HDR_LEN_IP   sizeof(struct ip)
#define HDR_LEN_UDP sizeof(struct udphdr)
struct arp_pkt {
        struct ether_header eh;
        struct ether_arp ea;
        u_char padding[18];
} req;

static unsigned char *s_frame_data = NULL;
static unsigned int   s_frame_size = 0;
static int            s_interface_index = -1;

static char *s_interface_name;

static unsigned char  s_interface_mac[ETH_ALEN];
static struct in_addr s_interface_ip;

int isATReading = 1;
int isMuxReading = 1;
int isSocketReading = 1;
int fd_at;
int fd_mux;
int fd_sk_raw = -1;
int listenfd;
int connfd;
int ser_id,st;
struct sockaddr_in addr_send;
struct ether_arp *fill_arp_packet(const unsigned char *src_mac_addr, \
           const char *src_ip, const char *dst_ip);

void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

unsigned char *fill_etherArp_packet(const char *if_name, const char *dst_ip)
{
    struct sockaddr_ll saddr_ll;
    struct ether_header *eth_header;
    struct ether_arp *arp_packet;
    struct ifreq ifr;
    unsigned char *buf = NULL;
    unsigned char src_mac_addr[ETH_ALEN];
    unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;
    char *src_ip;
    int sock_raw_fd, ret_len, i;

    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
        err_exit("socket()");

    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    /* 网卡接口名 */
    memcpy(ifr.ifr_name, if_name, strlen(if_name));

    /* 获取网卡接口索引 */
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) == -1)
        err_exit("ioctl() get ifindex");
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;

    /* 获取网卡接口IP */
    if (ioctl(sock_raw_fd, SIOCGIFADDR, &ifr) == -1)
        err_exit("ioctl() get ip");
    src_ip = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
    printf("local ip:%s\n", src_ip);

    /* 获取网卡接口MAC地址 */
    if (ioctl(sock_raw_fd, SIOCGIFHWADDR, &ifr))
        err_exit("ioctl() get mac");
    memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    printf("local mac");
    for (i = 0; i < ETH_ALEN; i++)
        printf(":%02x", src_mac_addr[i]);
    printf("\n");

    bzero(buf, ETHER_ARP_PACKET_LEN);
    /* 填充以太首部 */
    eth_header = (struct ether_header *)buf;
    memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);
    memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_ARP);
    /* arp包 */
    arp_packet = fill_arp_packet(src_mac_addr, src_ip, dst_ip);
    memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);
    return buf;
}

/* 填充arp包 */
struct ether_arp *fill_arp_packet(const unsigned char *src_mac_addr, const char *src_ip, const char *dst_ip)
{
    struct ether_arp *arp_packet;
    struct in_addr src_in_addr, dst_in_addr;
    unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;

    /* IP地址转换 */
    inet_pton(AF_INET, src_ip, &src_in_addr);
    inet_pton(AF_INET, dst_ip, &dst_in_addr);

    /* 整个arp包 */
    arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
    arp_packet->arp_hrd = htons(ARPHRD_ETHER);
    arp_packet->arp_pro = htons(ETHERTYPE_IP);
    arp_packet->arp_hln = ETH_ALEN;
    arp_packet->arp_pln = IP_ADDR_LEN;
    arp_packet->arp_op = htons(ARPOP_REQUEST);
    memcpy(arp_packet->arp_sha, src_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_tha, dst_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_spa, &src_in_addr, IP_ADDR_LEN);
    memcpy(arp_packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);

    return arp_packet;
}

int ReadData(int fd, char *rcv_buf,int data_len)
{
    int len,fs_sel;
    fd_set fs_read;
    
    struct timeval time;
    
    FD_ZERO(&fs_read);
    FD_SET(fd,&fs_read);
    
    time.tv_sec = 0;//non-block
    time.tv_usec = 0;
    fs_sel = select(fd+1,&fs_read,NULL,NULL,&time);
    if(fs_sel){
        len = read(fd,rcv_buf,data_len);
        return len;
    } else {
        return -1;
    }    
}

int WriteData(int fd, char *send_buf,int data_len)
{
    int ret;
    ret = write(fd,send_buf,data_len);
    if(ret > 0){
        if (data_len > ret){
            print_log("warning: write error, we missed data!");
        }
        return ret;
    } else {
        tcflush(fd,TCOFLUSH);
        return -1;
    }
}

static void *at_read( void *param )
{
    int ret = 0;
    char read_buf[1025];
    ssize_t sd_size;

    while (isATReading){
        memset(read_buf, 0, sizeof(read_buf));
        ret = ReadData(fd_at, read_buf, 1024);
        if(ret > 0){
            print_log("at_read, len=%d\n", ret);
                sd_size=sendto(st, read_buf, strlen(read_buf), 0, (struct sockaddr *)&addr_send,sizeof(addr_send));
            if(sd_size==-1)
            {
                print_err("sendto fail:%s\n",strerror(errno));
                break;
            }
            print_log("socket send data, len=%d\n", (int)sd_size);

            read_buf[ret]='\0';
            print_log("%s\n", read_buf);
            usleep(100000);
        } else {
            sleep(1);
        }
    }
    close(fd_at);
    printf("at_read thread exit.\n");
    return NULL;
}

static void *mux_read( void *param)
{
    int ret = 0;
    ssize_t sd_size;
    char read_buf[ETH_FRAME_LEN];
    uint16_t ether_type = 0;

    while (isMuxReading){
        memset(read_buf, 0, sizeof(read_buf));
        ret = ReadData(fd_mux, read_buf, ETH_FRAME_LEN);
        if(ret > HEAD_LEN_IP_TRANS){
            //ether data, send by socket_raw
            if((read_buf[0]==0x55)&&(read_buf[1]==0x10))
            {
                int frame_size = 0;
                frame_size = ret - HEAD_LEN_IP_TRANS;
                char buf_remove_head[frame_size];
                int i = 0;
                while(i<frame_size)
                {
                    buf_remove_head[i]=read_buf[i+2];
                    i++;
                }
                struct ip *iph           = NULL;
                struct ether_header *eth = NULL;
                struct ether_arp    *arp = NULL;
                
                eth = (struct ether_header*)buf_remove_head;
                ether_type = htons(eth->ether_type);

				switch(ether_type) {
				    case ETHERTYPE_ARP: {
				    	arp = (struct ether_arp*)(buf_remove_head + HDR_LEN_ETH);
				    	#if xdebug
		                    printf("++++++++++++++++recieve ETHERTYPE_ARP from CP+++++++++++++++++\n");
		                    printf("========frame size:%d\n", frame_size);
		                    dump_frame_ether(eth);
		                    dump_frame_arp  (arp);
		                    dump_frame_byte(read_buf,ret);
		                    printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		                    printf("\n");
		                #endif
				    	break;
				    }
				    case ETHERTYPE_IP: {
				    	iph   = (struct ip*)(buf_remove_head + HDR_LEN_ETH);
				        #if xdebug
				            printf("+++++++++++++++++++recieve ETHERTYPE_IP from cp++++++++++++++++++++++\n");
				            printf("========frame size:%d\n", frame_size);
				            dump_frame_ether(eth);
				            dump_frame_ip(iph);
				            dump_frame_byte(read_buf,ret);
				            printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
				            printf("\n");
				        #endif
				    	break;
				    }
				    default: {
				    	break;
				    }
				}
                
                if (frame_size != send_frame_ether( buf_remove_head, frame_size, s_interface_index, fd_sk_raw)) {
                    printf("send ether_frame error!\n");
                }
                print_log("send frame_mac success. len=%d\n", frame_size);
            }
            else{//mux data, send by socket
                sd_size=sendto(st, read_buf, ret, 0, (struct sockaddr *)&addr_send,sizeof(addr_send));
                if(sd_size==-1)
                {
                    print_err("sendto fail:%s\n",strerror(errno));
                    break;
                }
                print_log("send mux data success, len=%d\n", (int)sd_size);
            }
        }
        else {
            sleep(1);
        }
    }
    close(fd_mux);
    printf("mux_read thread exit.\n");
    return NULL;
}

static void *socket_read(void* arg)
{
    int ret;
    //recv message
    char read_buf[1024];
    struct sockaddr_in client_addr;
    socklen_t len=sizeof(client_addr);
    while (isSocketReading)
    {
        memset(read_buf,0,sizeof(read_buf));
        memset(&client_addr,0,sizeof(client_addr));
        ret = recvfrom(ser_id, read_buf, sizeof(read_buf), 0, (struct sockaddr *)&client_addr, &len);
        if(ret == -1)
        {
            print_err("recvfrom fail: %s\n",strerror(errno));
            break;
        }
        else
        {
            int retw;
            char buf_remove_head[ret-HEAD_LEN_MUX];
            //check if start with 'at/AT'
            if((read_buf[0]=='a'||read_buf[0]=='A') && (read_buf[1]=='t'||read_buf[1]=='T')){
                strcat(read_buf, "\r\n");
                retw = WriteData(fd_at, read_buf, ret+2);
                if(-1 == retw){
                    printf("write fd_at error!\n");
                    exit(1);
                }
                print_log("write to fd_at, len=%d\n", retw);
                //inet_ntoa(client_addr) get client IP
                print_log("%s server recv is %s\n",inet_ntoa(client_addr.sin_addr), read_buf);
            }else if(ret > 9){
                retw = WriteData(fd_mux, read_buf, ret);
                if(-1 == retw){
                    printf("write fd_mux error!\n");
                    exit(1);
                }
                print_log("write to fd_mux, len=%d\n", retw);
                strncpy(buf_remove_head, read_buf + 9,ret - 9);
                buf_remove_head[ret-9]='\0';
                print_log("%s server recv is %s\n",inet_ntoa(client_addr.sin_addr), buf_remove_head);
            }
        }
    }
    close(ser_id);
    printf("socket_read thread exit.\n");
    return NULL;
}

//-----------socket_raw begin---------------------------------------------------
static void *socket_raw_read(const char *dst_ip)
{
    while(1) {
        uint16_t ether_type = 0;
        struct ether_header* eth = NULL;
        struct ip 			*iph = NULL;
        struct ether_arp    *arp = NULL;
        
        memset(s_frame_data, 0x00, sizeof(unsigned char)*ETH_FRAME_LEN);
/*        
        s_frame_size = recv_frame_ether(s_frame_data, ETH_FRAME_LEN, \
            s_interface_index, fd_sk_raw);
*/
        
        s_frame_data = fill_etherArp_packet(s_interface_name,dst_ip);

        eth = (struct ether_header*)s_frame_data;
        ether_type = htons(eth->ether_type);

        switch(ether_type) {
            case ETHERTYPE_ARP: {
                arp = (struct ether_arp*)(s_frame_data + HDR_LEN_ETH);
                printf("arp_spa=%d.%d.%d.%d\n", \
                    arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], \
                    arp->arp_spa[3]);
                printf("arp_tpa=%d.%d.%d.%d\n", \
                    arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], \
                    arp->arp_tpa[3]);
				
                //printf("ip_local=%s  \n", inet_ntoa(s_interface_ip));
                
                printf("ip_local=%d.%d.%d.%d\n", \
                    s_interface_ip.s_addr&0xff, (s_interface_ip.s_addr>>8)&0xff, (s_interface_ip.s_addr>>16)&0xff, \
                    (s_interface_ip.s_addr>>24)&0xff);
                
                if( (((s_interface_ip.s_addr&0xff) == arp->arp_spa[0]) && \
                        (((s_interface_ip.s_addr>>8)&0xff) == arp->arp_spa[1]) && \
                        (((s_interface_ip.s_addr>>16)&0xff) == arp->arp_spa[2]) && \
                        (((s_interface_ip.s_addr>>24)&0xff) == arp->arp_spa[3]) ) \
                || (((s_interface_ip.s_addr&0xff) == arp->arp_tpa[0]) && \
                        (((s_interface_ip.s_addr>>8)&0xff) == arp->arp_tpa[1]) && \
                        (((s_interface_ip.s_addr>>16)&0xff) == arp->arp_tpa[2]) && \
                        (((s_interface_ip.s_addr>>24)&0xff) == arp->arp_tpa[3]) ) )
               	{
                    printf("data throw away!\n");
               	}
                else
                {
                    char buf_add_flag[ETH_FRAME_LEN + 2];
                    int i=0;
                    memset(buf_add_flag,'\0',sizeof(buf_add_flag));
                    buf_add_flag[0] = 0x55;
                    buf_add_flag[1] = 0x09;

                    //add head
                    while(i<s_frame_size)
                    {
                        buf_add_flag[i+2]=s_frame_data[i];
                        i++;
                    }
                    #if xdebug
                        printf("++++++++++++++++receive ETHERTYPE_ARP from AP++++++++++++++++++\n");
                        printf("========frame size:%d\n", s_frame_size);
                        dump_frame_ether(eth);
                        dump_frame_arp  (arp);
                        dump_frame_byte(buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS);
                        printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        printf("\n");
                    #endif
                
                    if(-1 == WriteData(fd_mux, buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS)){
                        printf("write to /dev/lmi2 error!\n");
                        exit(1);
                    }
                    printf("data write to /dev/lmi2 success!\n");
                }
                break;
            }
            case ETHERTYPE_IP: {
            	iph = (struct ip*)(s_frame_data + HDR_LEN_ETH);
            	printf("ip_src=%s  \n", inet_ntoa(iph->ip_src));
    			printf("ip_dst=%s  \n", inet_ntoa(iph->ip_dst));
            	printf("ip_local=%s  \n", inet_ntoa(s_interface_ip));
            	
               	if((iph->ip_src.s_addr == s_interface_ip.s_addr) || (iph->ip_dst.s_addr == s_interface_ip.s_addr))
               	{
                    printf("data throw away!\n");
               	}
                else
                {
                    char buf_add_flag[ETH_FRAME_LEN + 2];
                    int i=0;
            memset(buf_add_flag,'\0',sizeof(buf_add_flag));
                    buf_add_flag[0] = 0x55;
                    buf_add_flag[1] = 0x09;
                    //add head
                    while(i<s_frame_size){
                        buf_add_flag[i+2]=s_frame_data[i];
                        i++;
                    }

                    #if xdebug
                        printf("++++++++++++++receive ETHERTYPE_IP from AP+++++++++++++++++++\n");
                        printf("========frame size:%d\n", s_frame_size);
                        dump_frame_ether(eth);
                        dump_frame_ip(iph);
                        dump_frame_byte(buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS);
                        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        printf("\n");
                    #endif
                    
                    if(-1 == WriteData(fd_mux, buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS)){
                        printf("write to /dev/lmi2 error!\n");
                        exit(1);
                    }
                    printf("data write to /dev/lmi2 success!\n");
                }
                break;
            }
            case ETHERTYPE_REVARP:{
            	printf("--------------------receive ETHERTYPE_REVARP from AP-----------\n");
            	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            	break;
            }
            default: {
                printf("----------------------ETHERTYPE_default------------------------\n");
                break;
            }
        }
    }
}

int dump_frame_byte(uint8_t *data, int size)
{
    int i;

    for(i=0; i<size; i++) {
        if((i%16) == 0) {
            printf( "[%02x] ", i/16 );
        }
        printf( "%02x ", data[i] );
        if(((i+1)%16) == 0) {
            printf( "\n" );
        }
    }
    printf( "\n" );
    return 0;
}

int dump_frame_ether(struct ether_header *eth)
{
    if (NULL == eth) {
        return -1;
    }

    printf("========frame ether========\n");
    printf("type :0x%04x\n", htons(eth->ether_type));
    printf("d-mac:%02x-%02x-%02x-%02x-%02x-%02x\n",\
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], \
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("s-mac:%02x-%02x-%02x-%02x-%02x-%02x\n",\
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], \
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    return 0;
}

int dump_frame_ip(struct ip *iph)
{
    if (NULL == iph) {
        return -1;
    }

    printf("========frame ip   ========\n");
    printf("ip_v  =0x%x\n", iph->ip_v             );
    printf("ip_hl =0x%x\n", iph->ip_hl            );
    printf("ip_tos=0x%x\n", iph->ip_tos           );
    printf("ip_len=0x%x\n", htons(iph->ip_len)    );
    printf("ip_id =0x%x\n", htons(iph->ip_id)     );
    printf("ip_off=0x%x\n", htons(iph->ip_off)    );
    printf("ip_ttl=0x%x\n", iph->ip_ttl           );
    printf("ip_p  =0x%x\n", iph->ip_p             );
    printf("ip_sum=0x%x\n", htons(iph->ip_sum)    );
    printf("ip_src=%s  \n", inet_ntoa(iph->ip_src));
    printf("ip_dst=%s  \n", inet_ntoa(iph->ip_dst));
    return 0;
}

int dump_frame_arp(struct ether_arp *arp)
{
    if (NULL == arp) {
        return -1;
    }

    printf("========frame arp  ========\n");
    printf("arp_hrd=%d    \n", htons(arp->arp_hrd));
    printf("arp_pro=0x%04x\n", htons(arp->arp_pro));
    printf("arp_op =%d    \n", htons(arp->arp_op));
    printf("arp_sdr=%02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d\n", \
        arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], \
        arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5], \
        arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], \
        arp->arp_spa[3]);
    printf("arp_tgr=%02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d\n", \
        arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], \
        arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5], \
        arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], \
        arp->arp_tpa[3]);
    return 0;
}

int send_frame_ether(uint8_t *frame, int size, int ifindex, int fd_sk_raw)
{
    struct sockaddr_ll sll;
    socklen_t          sln = 0;

    struct sockaddr_ll *psll = NULL;

    if (-1 !=  ifindex) {
        bzero(&sll, sizeof(sll));
        sll.sll_ifindex  = ifindex;
        sll.sll_family   = PF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);

        psll = &sll;
        sln  = sizeof(struct sockaddr_ll);
    }

    size = sendto(fd_sk_raw, frame, size, 0, (struct sockaddr*)psll, sln);
    if (size < 0) {
        print_err("ioctl() SIOCGIFINDEX failed! errno=%d (%s)\n", \
            errno, strerror(errno));
    }

    return size;
}

int recv_frame_ether(uint8_t *frame, int size, int ifindex, int fd_sk_raw)
{
    struct sockaddr_ll sll;
    socklen_t          sln = sizeof(struct sockaddr_ll);

    struct sockaddr_ll *psll = NULL;
    socklen_t          *psln = NULL;

    if (NULL==frame || size<=0) {
        print_err("param failed! frame=%p size=%d\n", frame, size);
        return -1;
    }

    if (-1 !=  ifindex) {
        bzero(&sll, sizeof(sll));
        sll.sll_ifindex  = ifindex;
        sll.sll_family   = PF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);

        psll = &sll;
        psln = &sln;
    }

    memset(frame, 0, size*sizeof(uint8_t));
    size = recvfrom(fd_sk_raw, frame, size, 0, (struct sockaddr*)psll, psln);

    if (size < 0) {
        print_err("recvfrom() failed! errno=%d (%s)\n", \
            errno, strerror(errno));
    }
    return size;
}

int send_mac_frame(int fd_sk_raw)
{
    struct ip *iph           = NULL;
    struct ether_header *eth = NULL;
    struct udphdr *udph       = NULL;

    eth   = (struct ether_header*)s_frame_data;
    iph   = (struct ip*)(s_frame_data + HDR_LEN_ETH);

#if xdebug
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("========frame size:%d\n", s_frame_size);
    dump_frame_ether(eth);
    dump_frame_ip(iph);
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("\n");
#endif

    if (s_frame_size != send_frame_ether( \
        s_frame_data, s_frame_size, s_interface_index, fd_sk_raw)) {
        return -1;
    }

    print_log("ok. size=%d\n", s_frame_size);
    return 0;
}
//-----------socket_raw end---------------------------------------------------

int main(int argc, char** argv)
{
    int ret_val = 0;
    if (argc < 3)
    {
        printf("argument: Program hostname port\n");
        return -1;
    }

    printf( "\n                   ahnService v1.0\n"
            "###############################################################\n"
            "##  a: Stop receive AT message.\n"
            "##  m: Stop receive Mux data.\n"
            "##  s: Stop receive Socket data.\n"
            "##  q: Exit.\n"
            "###############################################################\n");
    sleep(3);
    //SERVER
    ser_id = socket(AF_INET, SOCK_DGRAM, 0);
    if (ser_id == -1)
    {
        print_err("socket fail%s\n", strerror(errno));
        return -1;
    }

    //UDP broadcast
    int on = 1;
    if (setsockopt(ser_id, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
        print_err("socked fail:%s\n", strerror(errno));
        return -1;
    }
    //set the IP structure that will be sent
    int myPort = atoi(argv[2]);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(myPort);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    //set bind
    if(bind(ser_id,(struct sockaddr *)&addr,sizeof(addr))==-1)
    {
        print_err("bind fail:%s\n",strerror(errno));
        return -1;
    }

    //CLIENT
    //set socket
    st=socket(AF_INET,SOCK_DGRAM,0);  
    if(st==-1)  
    {
        print_err("socket fail%s\n",strerror(errno));
        return -1;
    }

    //UDP broadcast
    on=1;
    if(setsockopt(st,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on))==-1)
    {
        print_err("socked fail:%s\n",strerror(errno));
        return -1;
    }

    //SOCKET_RAW
    fd_sk_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_sk_raw < 0) {
        print_err("socket() failed! errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    } 

    struct ifreq ifr;
    
    char *src_ip = NULL;
    src_ip = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
    printf("local ip:%s\n", src_ip);

    //set the IP structure that will be sent  
    memset(&addr_send,0,sizeof(addr_send));
    addr_send.sin_family=AF_INET;
    addr_send.sin_port=htons(myPort);
    addr_send.sin_addr.s_addr=inet_addr(src_ip);

    bzero(&ifr,sizeof(ifr));
    strcpy(ifr.ifr_name, "rndis0");
    /* 获取网卡接口IP */
    if (ioctl(fd_sk_raw, SIOCGIFADDR, &ifr) == -1)
        err_exit("ioctl() get ip");

    s_interface_name = ifr.ifr_name;
    if (-1 == ioctl(fd_sk_raw, SIOCGIFINDEX, &ifr)) {
        print_err("ioctl() SIOCGIFINDEX failed! errno=%d (%s)\n", \
            errno, strerror(errno));
        return -1;
    }
    s_interface_index = ifr.ifr_ifindex;

    if (-1 == ioctl(fd_sk_raw, SIOCGIFHWADDR, &ifr)) {
        print_err("ioctl() SIOCGIFHWADDR failed! errno=%d (%s)\n", \
            errno, strerror(errno));
        return -1;
    }
    memcpy(s_interface_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (-1 == ioctl(fd_sk_raw, SIOCGIFADDR, &ifr)) {
        print_err("ioctl() SIOCGIFADDR failed! errno=%d (%s)\n", \
            errno, strerror(errno));
        return -1;
    }
    s_interface_ip.s_addr = \
        ((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr.s_addr;

    if (-1 == ioctl(fd_sk_raw, SIOCGIFFLAGS, &ifr)) {
        print_err("ioctl() IFF_PROMISC failed! errno=%d (%s)\n", \
            errno, strerror(errno));
        return -1;
    }

    if ((ifr.ifr_flags&IFF_PROMISC) != IFF_PROMISC) {
        ifr.ifr_flags |= IFF_PROMISC;
        if(-1 == ioctl(fd_sk_raw, SIOCSIFFLAGS, &ifr)) {
            print_err("ioctl() IFF_PROMISC failed! errno=%d (%s)\n", \
                errno, strerror(errno));
            return -1;
        }
    }

    int nBufLen = 2*1024*1024; //recv_buf is 2M
    if(setsockopt(fd_sk_raw,SOL_SOCKET,SO_RCVBUF,(char*)&nBufLen, sizeof(nBufLen))==-1)
    {
        print_err("setsockopt fail:%s\n",strerror(errno));
        return -1;
    }

    printf("========host info  ========\n");
    printf("ifr_ifindex=%d %s\n", s_interface_index, "rndis0");
    printf("ifr_hwaddr =%02x-%02x-%02x-%02x-%02x-%02x\n", \
        s_interface_mac[0], s_interface_mac[1], s_interface_mac[2], 
        s_interface_mac[3], s_interface_mac[4], s_interface_mac[5]);
    printf("ifr_addr   =%s\n", inet_ntoa(s_interface_ip));
    printf("ifr_flags  =IFF_PROMISC\n");
    printf("pid        =0x%x\n", getpid());
    printf("header_eth =%d\n", HDR_LEN_ETH);
    printf("header_ip  =%d\n", HDR_LEN_IP);
    printf("\n");

    fd_at = open(AT_DEV, O_RDWR|O_NOCTTY);
    if(-1 == fd_at){
        printf("open at_dev error\n");
        exit(1);
    }
    printf("open %s,  fd: %d\n", AT_DEV, fd_at);

    fd_mux = open(MUX_DEV, O_RDWR|O_NOCTTY);
    if(-1 == fd_mux){
        printf("open mux_dev error\n");
        exit(1);
    }
    printf("open %s, fd: %d\n", MUX_DEV, fd_mux);

    pthread_t tid_socket_read, tid_at_read, tid_mux_read, tid_socketraw_read;

    ret_val = pthread_create(&tid_at_read, NULL, at_read, NULL);
    if(ret_val != 0){
        printf("Fail to create thread at_read: %d \n", ret_val);
    }

    ret_val = pthread_create(&tid_mux_read, NULL, mux_read, NULL);
    if( ret_val != 0 ){
        printf("Fail to create thread mux_read: %d \n", ret_val);
    }

    if(pthread_create(&tid_socket_read,NULL,socket_read,NULL))
    {
        printf("pthread_create socket_read err\n");
    }

    if(pthread_create(&tid_socketraw_read,NULL,socket_raw_read,argv[1]))
    {
        printf("pthread_create socket_read err\n");
    }

    while(1){
        char cmd = getchar();
        if(cmd == 'q'){
            break;
        }else if(cmd == 'a'){
            isATReading = 0;
        }else if(cmd == 'm'){
            isMuxReading = 0;
        }else if(cmd == 's'){
            isSocketReading = 0;
        }
        sleep(1);
    }
    close(st);
    printf("main thread exit.\n");
    return 0;
}
