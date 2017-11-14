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
*  Date             Author          Description
*-------------------------------------------------------------------------------------------------
*  2017-07-12       qige            create
*  2017-08-04       qige            init 4 thread: at_read,mux_read,socket_read,socket_raw_read;
*  2017-08-17       qige            finish socket_raw_read & mux_read;
**************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>//ether_arp
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <time.h>
#include <sys/timeb.h>
#include <stdarg.h>

#define uchar unsigned char
#define LOG_FILE "/data/local/ahnLog.log"
#define AT_DEV "/dev/TTYEMS30"
#define MUX_DEV "/dev/lmi2"
#define HEAD_LEN_MUX 9
#define HEAD_LEN_IP_TRANS 2

#define print_log(fmt, ...) \
    fprintf(flog,"[%04d]%s() " fmt, __LINE__, __FUNCTION__, ####__VA_ARGS__)
#define print_err(fmt, ...) \
    fprintf(flog,"[%04d]%s() err: " fmt, __LINE__, __FUNCTION__, ####__VA_ARGS__)

#define xdebug 1
#define xunused __attribute__((unused))

#define HDR_LEN_ETH  sizeof(struct ether_header)
#define HDR_LEN_IP   sizeof(struct ip)
#define HDR_LEN_UDP sizeof(struct udphdr)

static uchar  s_frame_data[ETH_FRAME_LEN];
static unsigned int   s_frame_size = 0;
static int            s_interface_index = -1;
static uchar  s_interface_mac[ETH_ALEN];
static struct in_addr s_interface_ip;

FILE *flog;
int isATReading = 1;
int isMuxReading = 1;
int isSocketvoiceReading = 1;
int isSocketatReading = 1;
int isSocketdataReading = 1;
int fd_at;
int fd_mux;
int fd_sk_raw = -1;
int listenfd;
int connfd;
int st,at_st,voice_st,data_st;
struct sockaddr_in addr;
struct sockaddr_in addr_send;
struct sockaddr_in addr_send_data;
struct sockaddr_in addr_send_voice;


int ReadData(int fd, uchar *rcv_buf,int data_len)
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

int WriteData(int fd, uchar *send_buf,int data_len)
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
unsigned short crc16 (uchar *buf, int len)
{
    unsigned short data, crc = 0;
    int i;
    for ( ;len > 0; len--, buf++) {
        data =((unsigned short) *buf) << 8;
        for (i = 0; i < 8; i++, data <<= 1) {
            if ((crc ^ data) & 0x8000)
                crc = (unsigned short) ((crc << 1) ^ 0x1021);
            else
                crc <<= 1;
        }
    }
    return crc;
}

int build_recv_udp(int port)
{
    int  ser_id=socket(AF_INET,SOCK_DGRAM,0);  
    if(ser_id==-1)  
    {
        print_err("socket fail%s\n",strerror(errno));
        return -1;
    }
    //UDP broadcast
    int on=1;
    if(setsockopt(ser_id,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on))==-1)
    {
        print_err("socket fail:%s\n",strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port); 
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (-1 == bind(ser_id, (struct sockaddr*)&addr, sizeof(addr)))// bind ser_id
	{
		print_err("bind fail:%s\n",strerror(errno));
		return -1;
	}
    return ser_id;
}

void add_data_header(unsigned char *temp_buffer,unsigned char *buffer,unsigned int len)
{
    unsigned short crc = 0;
    unsigned char *temp;

    crc = crc16(buffer,len);
    temp_buffer[0] = 0xCE;
    temp_buffer[1] = 0x10;

    temp_buffer[2] = (len>>8)&0xff;

    temp_buffer[3] = len&0xFF;

    temp_buffer[4] = (crc>>8)&0xff;
    temp_buffer[5] = crc&0xFF;
    temp_buffer[6] = 0xCE;
    memcpy(temp_buffer+7,buffer,len);
    temp_buffer[len+7] = 0xCE;
}
void add_data_header_voice(unsigned char *temp_buffer,unsigned char *buffer,unsigned int len)
{
    unsigned char *temp;

    temp_buffer[0] = 0xCF;
    temp_buffer[1] = 0xCE;

    temp_buffer[2] = 0x10;

    temp_buffer[3] = 0xCE;
    memcpy(temp_buffer+4,buffer,len);
    temp_buffer[len+4] = 0xCE;
	temp_buffer[len+5] = 0xCF;
}

static void *at_read( void *param )
{
    int ret = 0;
    uchar read_buf[1025]={0};
    uchar *read_temp_buf;
    ssize_t sd_size;

    while (isATReading){
        ret = ReadData(fd_at, read_buf, 1024);
        // print_log("%s\n", read_buf);
        if(ret > 0){
            print_log("at_read, len=%d\n", ret);
			uchar read_temp_buf[1024+8]={0};
            add_data_header(read_temp_buf,read_buf,ret);
            print_log("%s\n", read_temp_buf);
            sd_size=sendto(st, read_temp_buf, ret+8, 0, (struct sockaddr *)&addr_send,sizeof(addr_send));

            if(sd_size==-1)
            {
                print_err("sendto fail:%s\n",strerror(errno));
                break;
            }
            print_log("socket send data, len=%d\n", (int)sd_size);

            usleep(100000);
        } else {
            usleep(100000);
        }
    }
    close(fd_at);
    fprintf(flog,"at_read thread exit.\n");
    return NULL;
}

static void *mux_read( void *param)
{
    int ret = 0;
    ssize_t sd_size;
    uchar read_buf[ETH_FRAME_LEN]={0};
    uint16_t ether_type = 0;
    uchar read_temp_buf[ETH_FRAME_LEN+8]={0};

    while (isMuxReading){
    	// print_log("isMuxReading!\n");
        ret = ReadData(fd_mux, read_buf, ETH_FRAME_LEN);
        if (ret==-1)
        {
        	continue;
        }
        if(ret > HEAD_LEN_IP_TRANS){
            //ether data, send by socket_raw
            print_log("get ret = %d\n",ret);
            dump_frame_byte(read_buf,ret);
            fprintf(flog,"++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            if((read_buf[0]==0x55)&&(read_buf[1]==0x10))
            {
                int frame_size = 0;
                frame_size = ret - HEAD_LEN_IP_TRANS;
                uchar buf_remove_head[frame_size];
                struct ip *iph           = NULL;
                struct ether_header *eth = NULL;
                struct ether_arp    *arp = NULL;
                
                memset(buf_remove_head,0,frame_size);
                memcpy(buf_remove_head,read_buf+2,frame_size);
                eth = (struct ether_header*)buf_remove_head;
                ether_type = htons(eth->ether_type);

                switch(ether_type) {
                    case ETHERTYPE_ARP: {
                        arp = (struct ether_arp*)(buf_remove_head + HDR_LEN_ETH);
                        #if xdebug
                            fprintf(flog,"+++++++++++recieve ETHERTYPE_ARP from CP+++++++++++++\n");
                            fprintf(flog,"========frame size:%d\n", frame_size);
                            dump_frame_ether(eth);
                            dump_frame_arp  (arp);
                            dump_frame_byte(read_buf,ret);
                            fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                            fprintf(flog,"\n");
                        #endif
                        if (frame_size != send_frame_ether( buf_remove_head, frame_size, s_interface_index, fd_sk_raw)) {
                            fprintf(flog,"send ether_frame arp error!\n");
                            }
                        print_log("send frame_mac arp success. len=%d\n", frame_size);
                        break;
                    }
                    case ETHERTYPE_IP: {
                        int data_offset = 0;
                        uchar * ip_read_buf;
                        ip_read_buf = read_buf;
                        while(ip_read_buf[0]==0x55 && ip_read_buf[1]==0x10)
                        {
                            iph   = (struct ip*)(ip_read_buf + HDR_LEN_ETH+2);
                            data_offset = htons(iph->ip_len) + HDR_LEN_ETH + HEAD_LEN_IP_TRANS;
                            uchar ip_buf_remove_head [data_offset-HEAD_LEN_IP_TRANS];
                            memset(ip_buf_remove_head,0,data_offset-HEAD_LEN_IP_TRANS);
                            memcpy(ip_buf_remove_head,ip_read_buf + HEAD_LEN_IP_TRANS,htons(iph->ip_len) + HDR_LEN_ETH);
                            
                            #if xdebug
                                fprintf(flog,"+++++++++++recieve ETHERTYPE_IP from cp++++++++++++++\n");
                                dump_frame_ether(eth);
                                dump_frame_ip(iph);
                                dump_frame_byte(ip_buf_remove_head,htons(iph->ip_len) + HDR_LEN_ETH);
                                fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                                fprintf(flog,"\n");
                            #endif

                            if ((data_offset-HEAD_LEN_IP_TRANS) != send_frame_ether(ip_buf_remove_head, htons(iph->ip_len) + HDR_LEN_ETH, s_interface_index, fd_sk_raw)) {
                                fprintf(flog,"send ether_frame error!\n");
                            }
                            print_log("send frame_mac success. len=%d\n", frame_size);
                            ip_read_buf = ip_read_buf+ data_offset;
                        } 
                        break;
                    }
                    default: {
                        break;
                    }
                }
            }
else if((read_buf[0]==0x55)&&((read_buf[1]==0x04)||(read_buf[1]==0x05)||(read_buf[1]==0x06))) 
	    {//mux voice, send by socket
            print_log(" mux voice reading! \n");
            add_data_header_voice(read_temp_buf,read_buf,ret);
            sd_size=sendto(st, read_temp_buf, ret+6, 0, (struct sockaddr *)&addr_send_voice,sizeof(addr_send_voice));
            if(sd_size==-1)
            {
                print_err("sendto fail:%s\n",strerror(errno));
                break;
            }
            #if xdebug
                fprintf(flog,"++++++++++++++++send to android data+++++++++++++++++\n");
                dump_frame_byte(read_temp_buf,sd_size);
                fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                print_log("send mux voice success, len=%d\n", (int)sd_size);
            #endif
        }
		else if((read_buf[0]==0x55)&&(read_buf[1]==0x08))
	    {//mux data, send by socket
            print_log(" mux data reading! \n");
            add_data_header(read_temp_buf,read_buf,ret);
                
                dump_frame_byte(read_temp_buf,ETH_FRAME_LEN+8);
                sd_size=sendto(st, read_temp_buf, ret+8, 0, (struct sockaddr *)&addr_send_data,sizeof(addr_send_data));
                if(sd_size==-1)
                {
                    print_err("sendto fail:%s\n",strerror(errno));
                    break;
                }
                #if xdebug
                    fprintf(flog,"++++++++++++++++send to android data+++++++++++++++++\n");
                    dump_frame_byte(read_temp_buf,sd_size);
                    fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    print_log("send mux data success, len=%d\n", (int)sd_size);
                #endif

            }
        }
        else {
            usleep(1000);
        }
    }
    close(fd_mux);
    fprintf(flog,"mux_read thread exit.\n");
    return NULL;
}

static void *socket_at_read(void* arg)
{
    print_log("socket_at_read FUNCTION  \n");
    int ret;
    //recv message
    uchar read_buf[1024];
    struct sockaddr_in client_addr;
    socklen_t len=sizeof(client_addr);
    while (isSocketatReading)
    {
        memset(read_buf,0,sizeof(read_buf));
        memset(&client_addr,0,sizeof(client_addr));
        ret = recvfrom(at_st, read_buf, sizeof(read_buf), 0, (struct sockaddr *)&client_addr, &len);
        #if xdebug
            print_log("start dump read_buf!!  \n");
            dump_frame_byte(read_buf,ret);
            print_log("ret=%d\n", ret);
        #endif
        if(ret == -1)
        {
            print_err("recvfrom fail: %s\n",strerror(errno));
            break;
        }
        else
        {
            int retw;
            uchar temp_buf[2000]={0};
            uchar *buf_data;
            buf_data=temp_buf;
            uchar high_crc,low_crc;
            unsigned short crc = 0;
            unsigned short len = 0;
            print_log("mux read first!\n");
            print_log("%s server all recv is \n",inet_ntoa(client_addr.sin_addr));
            dump_frame_byte(read_buf,ret);
            fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            if((read_buf[0]==0xCE)&&(read_buf[ret-1]==0xCE))
            {
                memcpy(buf_data, read_buf + 7,ret - 8);
                crc = crc16(buf_data,ret - 8);
	
                low_crc = crc>>8;
                high_crc = crc&0xFF;

                len=((read_buf[2]<<8)|read_buf[3]);
                if((read_buf[4]==low_crc)&&(read_buf[5]==high_crc))
                {
                	print_log("crc is right!\n");
                    if(len==ret-8)
                    {   
                        if(read_buf[1]==0x10)
                        {
                            if((read_buf[7]=='a'||read_buf[7]=='A') && (read_buf[8]=='t'||read_buf[8]=='T'))
                            {
                                strcat(buf_data, "\r\n");
                                retw = WriteData(fd_at, buf_data, ret-6);
                                if(-1 == retw)
                                {
                                    fprintf(flog,"write fd_at error!\n");
                                    sleep(1);
                                    retw = WriteData(fd_at, buf_data, ret-6);
				                    if (-1 == retw)
				                    {
				                    	fprintf(flog,"write fd_mux error!\n");
				                    }
                                }

                                #if xdebug
                                    print_log("write to fd_at, len=%d\n", retw);
                                    //inet_ntoa(client_addr) get client IP
                                    print_log("%s server recv is %s\n",inet_ntoa(client_addr.sin_addr), buf_data);
                                #endif
                            }
						} 
					}
				}
			}
        }
		usleep(1000);
    }
    close(at_st);
    fprintf(flog,"socket_at_read thread exit.\n");
    return NULL;
}

static void *socket_data_read(void* arg)
{
    print_log("socket_data_read FUNCTION  \n");
    int ret;
    //recv message
    uchar read_buf[1024];
    struct sockaddr_in client_addr;
    socklen_t len=sizeof(client_addr);
    while (isSocketdataReading)
    {
    	print_log("data isSocketReading!  \n");
        memset(read_buf,0,sizeof(read_buf));
        memset(&client_addr,0,sizeof(client_addr));
        ret = recvfrom(data_st, read_buf, sizeof(read_buf), 0, (struct sockaddr *)&client_addr, &len);
        #if xdebug
            print_log("start dump socket_data_read read_buf!!  \n");
            dump_frame_byte(read_buf,ret);
            print_log("ret=%d\n", ret);
        #endif
        if(ret == -1)
        {
            print_err("recvfrom fail: %s\n",strerror(errno));
            break;
        }
        else
        {
            int retw;
            uchar temp_buf[2000]={0};
            uchar *buf_data;
            buf_data=temp_buf;
            uchar high_crc,low_crc;
            unsigned short crc = 0;
            unsigned short len = 0;
            #if xdebug
                print_log("mux read first!\n");
                print_log("%s server all recv is \n",inet_ntoa(client_addr.sin_addr));
                dump_frame_byte(read_buf,ret);
                fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            #endif
            if((read_buf[0]==0xCE)&&(read_buf[ret-1]==0xCE))
            {
                memcpy(buf_data, read_buf + 7,ret - 8);
                crc = crc16(buf_data,ret - 8);
	
                low_crc = crc>>8;
                high_crc = crc&0xFF;

                len=((read_buf[2]<<8)|read_buf[3]);
                if((read_buf[4]==low_crc)&&(read_buf[5]==high_crc))
                {
                	print_log("crc is right!\n");
                    if(len==ret-8)
                    {   
                        if(read_buf[1]==0x10)
                        {
                            if(ret>16)
                            {
                                retw = WriteData(fd_mux, buf_data, ret-8);
                                if(-1 == retw)
                                {
                                    fprintf(flog,"write fd_mux error!\n");
                                    sleep(1);
                                    retw = WriteData(fd_mux, buf_data, ret-8);
					                if (-1 == retw)
					                {
					                	fprintf(flog,"write fd_mux error!\n");
					                }
					            }
                                #if xdebug
                                    print_log("write data to fd_mux, len=%d\n", retw);
                                    buf_data[ret-8]='\0';
    				                print_log("%s socket_data_read server all recv is \n",inet_ntoa(client_addr.sin_addr));
    				                dump_frame_byte(read_buf,ret);
                                    fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                                #endif
                            }
							else if(read_buf[7] == 0x55 && read_buf[8]== 0x0A)
                            {
                                retw = WriteData(fd_mux, buf_data, ret-8);
                                if(-1 == retw){
                                    fprintf(flog,"write fd_mux traffic control message error!\n");
                                    sleep(1);
                                    retw = WriteData(fd_mux, buf_data, ret-8);
                                    if (-1 == retw)
                                    {
                                        fprintf(flog,"write fd_mux traffic control message error!\n");
                                    }
                                }
                                #if xdebug
                                    print_log("write to fd_mux is traffic control message\n");
                                    print_log("write to fd_mux, len=%d\n", retw);
                                #endif
                            }
                        }
                    }
                }
            }
        }
		usleep(1000);
    }
    close(data_st);
    fprintf(flog,"socket_data_read thread exit.\n");
    return NULL;
}

static void *socket_voice_read(void* arg)
{
    print_log("socket_voice_read FUNCTION  \n");
    int ret;
    //recv message
    uchar read_buf[1024];
    struct sockaddr_in client_addr;
    socklen_t len=sizeof(client_addr);
    while (isSocketvoiceReading)
    {
    	print_log("voice isSocketReading!  \n");
        memset(read_buf,0,sizeof(read_buf));
        memset(&client_addr,0,sizeof(client_addr));
        ret = recvfrom(voice_st, read_buf, sizeof(read_buf), 0, (struct sockaddr *)&client_addr, &len);

        #if xdebug
            print_log("start dump socket_voice_read read_buf!!  \n");
            dump_frame_byte(read_buf,ret);
            print_log("ret=%d\n", ret);
        #endif

        if(ret == -1)
        {
            print_err("recvfrom fail: %s\n",strerror(errno));
            break;
        }
        else
        {
            int retw;
            uchar temp_buf[2000]={0};
            uchar *buf_data;
            buf_data=temp_buf;
            uchar high_crc,low_crc;
            unsigned short crc = 0;
            unsigned short len = 0;
            #if xdebug
                print_log("mux read first!\n");
                print_log("%s server all recv is \n",inet_ntoa(client_addr.sin_addr));
                dump_frame_byte(read_buf,ret);
                fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            #endif
			if((read_buf[0]==0xCF)&&(read_buf[ret-1]==0xCF))
			{
				print_log("recv voive data\n");
				if(ret>13)
				{
					memcpy(buf_data, read_buf + 4,ret - 6);
					if((read_buf[1]==0xCE)&&(read_buf[ret-2]==0xCE)&&(read_buf[2]==0x10)&&(read_buf[3]==0xCE))
					{
					 	retw = WriteData(fd_mux, buf_data, ret-6);
                     	if(-1 == retw)
                     	{
                            fprintf(flog,"write fd_mux error!\n");
                            sleep(1);
                            retw = WriteData(fd_mux, buf_data, ret-6);
                            if (-1 == retw)
                            {
                                fprintf(flog,"write fd_mux error!\n");
                            }
                     		// exit(1);
                     	}
                        #if xdebug
                            print_log("write voice to fd_mux, len=%d\n", retw);
                            buf_data[ret-6]='\0';
                            print_log("%s write voice to fd_mux, is:\n",inet_ntoa(client_addr.sin_addr));
                            dump_frame_byte(buf_data,retw);
                            fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        #endif
					}
				}	
			}
        }
        usleep(1000);
    }
    close(voice_st);
    fprintf(flog,"socket_voice_read thread exit.\n");
    return NULL;
}

//-----------socket_raw begin---------------------------------------------------
static void *socket_raw_read(void* arg)
{
    while(1) {
        uint16_t ether_type = 0;
        struct ether_header* eth = NULL;
        struct ip           *iph = NULL;
        struct ether_arp    *arp = NULL;
        
        memset(s_frame_data, 0x00, sizeof(uchar)*ETH_FRAME_LEN);
        s_frame_size = recv_frame_ether(s_frame_data, ETH_FRAME_LEN, \
            s_interface_index, fd_sk_raw);

        eth = (struct ether_header*)s_frame_data;
        ether_type = htons(eth->ether_type);

        switch(ether_type) {
            case ETHERTYPE_ARP: {
                arp = (struct ether_arp*)(s_frame_data + HDR_LEN_ETH);
                
                #if xdebug
                    fprintf(flog,"arp_spa=%d.%d.%d.%d\n", \
                        arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], \
                        arp->arp_spa[3]);
                    fprintf(flog,"arp_tpa=%d.%d.%d.%d\n", \
                        arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], \
                        arp->arp_tpa[3]);
                
                //printf("ip_local=%s  \n", inet_ntoa(s_interface_ip));
                
                    fprintf(flog,"ip_local=%d.%d.%d.%d\n", \
                        s_interface_ip.s_addr&0xff, (s_interface_ip.s_addr>>8)&0xff, (s_interface_ip.s_addr>>16)&0xff, \
                        (s_interface_ip.s_addr>>24)&0xff);
                #endif
                if( (((s_interface_ip.s_addr&0xff) == arp->arp_spa[0]) && \
                        (((s_interface_ip.s_addr>>8)&0xff) == arp->arp_spa[1]) && \
                        (((s_interface_ip.s_addr>>16)&0xff) == arp->arp_spa[2]) && \
                        (((s_interface_ip.s_addr>>24)&0xff) == arp->arp_spa[3]) ) \
                || (((s_interface_ip.s_addr&0xff) == arp->arp_tpa[0]) && \
                        (((s_interface_ip.s_addr>>8)&0xff) == arp->arp_tpa[1]) && \
                        (((s_interface_ip.s_addr>>16)&0xff) == arp->arp_tpa[2]) && \
                        (((s_interface_ip.s_addr>>24)&0xff) == arp->arp_tpa[3]) ) )
                {
                    fprintf(flog,"data throw away!\n");
                }

                // else if (arp->arp_tpa[2] > 20 || arp->arp_tpa[3] > 20)
    //             {
    //                 fprintf(flog,"fault ip addr, data throw away!\n");
    //             }
                else
                {
                    uchar buf_add_flag[ETH_FRAME_LEN + 2];
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
                        fprintf(flog,"+++++++++receive ETHERTYPE_ARP from AP+++++++++++++++\n");
                        fprintf(flog,"========frame size:%d\n", s_frame_size);
                        dump_frame_ether(eth);
                        dump_frame_arp  (arp);
                        dump_frame_byte(buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS);
                        fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        fprintf(flog,"\n");
                    #endif
                
                    if(-1 == WriteData(fd_mux, buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS)){
                        fprintf(flog,"write to /dev/lmi2 error!\n");
//                        exit(1);
                        sleep(1);
                        if(-1 == WriteData(fd_mux, buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS)){
                           fprintf(flog,"write to /dev/lmi2 error!\n"); 
                        }
                    }
                    fprintf(flog,"data write to /dev/lmi2 success!\n");
                }
                break;
            }
            case ETHERTYPE_IP: {
                iph = (struct ip*)(s_frame_data + HDR_LEN_ETH);
                #if xdebug
                    fprintf(flog,"ip_src=%s  \n", inet_ntoa(iph->ip_src));
                    fprintf(flog,"ip_dst=%s  \n", inet_ntoa(iph->ip_dst));
                    fprintf(flog,"ip_local=%s  \n", inet_ntoa(s_interface_ip));
                #endif


                if((iph->ip_src.s_addr == s_interface_ip.s_addr) || (iph->ip_dst.s_addr == s_interface_ip.s_addr))
                {
                    fprintf(flog,"data throw away!\n");
                }
                else if ((htonl(iph->ip_dst.s_addr)>>16) ==0xc0a8&&((htonl(iph->ip_dst.s_addr)&0xff)!=255))
                {
                    uchar buf_add_flag[ETH_FRAME_LEN + 2];
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
                        fprintf(flog,"+++++++++++receive ETHERTYPE_IP from AP++++++++++++++\n");

                        fprintf(flog,"========frame size:%d\n", s_frame_size);
                        dump_frame_ether(eth);
                        dump_frame_ip(iph);
                        dump_frame_byte(buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS);
                        fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                        fprintf(flog,"\n");
                    #endif

                    if(-1 == WriteData(fd_mux, buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS)){
                        fprintf(flog,"write to /dev/lmi2 error!\n");
//                        exit(1);
                        sleep(1);
                        if(-1 == WriteData(fd_mux, buf_add_flag, s_frame_size + HEAD_LEN_IP_TRANS)){
                           fprintf(flog,"write to /dev/lmi2 error!\n"); 
                        }
                    }
                    fprintf(flog,"data write to /dev/lmi2 success!\n");
                }
                else
                {
                    fprintf(flog,"fault ip addr, data throw away!\n");
                }
                break;
            }
            case ETHERTYPE_REVARP:{
                #if xdebug
                    fprintf(flog,"++++++++receive ETHERTYPE_REVARP from AP+++++++++++++\n");
                    fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                    fprintf(flog,"+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
                #endif
                break;

            }
            default: {
                fprintf(flog,"++++++++++++ETHERTYPE_default+++++++++++++\n");
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
            fprintf(flog, "[%02x] ", i/16 );
        }
        fprintf(flog, "%02x ", data[i] );
        if(((i+1)%16) == 0) {
            fprintf(flog, "\n" );
        }
    }
    fprintf(flog, "\n" );
    return 0;
}

int dump_frame_ether(struct ether_header *eth)
{
    if (NULL == eth) {
        return -1;
    }

    fprintf(flog,"========frame ether========\n");
    fprintf(flog,"type :0x%04x\n", htons(eth->ether_type));
    fprintf(flog,"d-mac:%02x-%02x-%02x-%02x-%02x-%02x\n",\
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], \
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    fprintf(flog,"s-mac:%02x-%02x-%02x-%02x-%02x-%02x\n",\
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], \
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    return 0;
}

int dump_frame_ip(struct ip *iph)
{
    if (NULL == iph) {
        return -1;
    }

    fprintf(flog,"========frame ip   ========\n");
    fprintf(flog,"ip_v  =0x%x\n", iph->ip_v             );
    fprintf(flog,"ip_hl =0x%x\n", iph->ip_hl            );
    fprintf(flog,"ip_tos=0x%x\n", iph->ip_tos           );
    fprintf(flog,"ip_len=0x%x\n", htons(iph->ip_len)    );
    fprintf(flog,"ip_id =0x%x\n", htons(iph->ip_id)     );
    fprintf(flog,"ip_off=0x%x\n", htons(iph->ip_off)    );
    fprintf(flog,"ip_ttl=0x%x\n", iph->ip_ttl           );
    fprintf(flog,"ip_p  =0x%x\n", iph->ip_p             );
    fprintf(flog,"ip_sum=0x%x\n", htons(iph->ip_sum)    );
    fprintf(flog,"ip_src=%s  \n", inet_ntoa(iph->ip_src));
    fprintf(flog,"ip_dst=%s  \n", inet_ntoa(iph->ip_dst));
    return 0;
}

int dump_frame_arp(struct ether_arp *arp)
{
    if (NULL == arp) {
        return -1;
    }

    fprintf(flog,"========frame arp  ========\n");
    fprintf(flog,"arp_hrd=%d    \n", htons(arp->arp_hrd));
    fprintf(flog,"arp_pro=0x%04x\n", htons(arp->arp_pro));
    fprintf(flog,"arp_op =%d    \n", htons(arp->arp_op));
    fprintf(flog,"arp_sdr=%02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d\n", \
        arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], \
        arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5], \
        arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], \
        arp->arp_spa[3]);
    fprintf(flog,"arp_tgr=%02x-%02x-%02x-%02x-%02x-%02x %d.%d.%d.%d\n", \
        arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], \
        arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5], \
        arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], \
        arp->arp_tpa[3]);
    return 0;
}
/**
**以太网发送
**/
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

//-----------socket_raw end---------------------------------------------------

int main(int argc, char** argv)
{
    flog=fopen(LOG_FILE,"w+");
    int on = 1;
    int ret_val = 0;
	int myPort = atoi(argv[2]);
    struct sockaddr_in addr;
    if (argc < 3)
    {
        fprintf(flog, "argument: Program hostname port\n");
        return -1;
    }

    fprintf(flog, "\n                   ahnService v1.0\n"
            "###############################################################\n"
            "##  a: Stop receive AT message.\n"
            "##  m: Stop receive Mux data.\n"
            "##  s: Stop receive Socket data.\n"
            "##  q: Exit.\n"
            "###############################################################\n");
	//SERVER
	at_st=build_recv_udp(62450);
	voice_st = build_recv_udp(62451);
	data_st = build_recv_udp(62452);
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

    //set the IP structure that will be sent  
    memset(&addr_send,0,sizeof(addr_send));
    addr_send.sin_family=AF_INET;
    addr_send.sin_port=htons(62450);
    addr_send.sin_addr.s_addr=inet_addr(argv[1]);
    //set the Voice structure that will be sent  
    memset(&addr_send_voice,0,sizeof(addr_send_voice));
    addr_send_voice.sin_family=AF_INET;
    addr_send_voice.sin_port=htons(62451);
    addr_send_voice.sin_addr.s_addr=inet_addr(argv[1]);

    //set the Data structure that will be sent  
    memset(&addr_send_data,0,sizeof(addr_send_data));
    addr_send_data.sin_family=AF_INET;
    addr_send_data.sin_port=htons(62452);
    addr_send_data.sin_addr.s_addr=inet_addr(argv[1]);

    //SOCKET_RAW
    fd_sk_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_sk_raw < 0) {
        print_err("socket() failed! errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    } 

    struct ifreq ifr;
    bzero(&ifr,sizeof(ifr));
    strcpy(ifr.ifr_name, "rndis0");
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

    fprintf(flog, "========host info  ========\n");
    fprintf(flog, "ifr_ifindex=%d %s\n", s_interface_index, "rndis0");
    fprintf(flog, "ifr_hwaddr =%02x-%02x-%02x-%02x-%02x-%02x\n", \
        s_interface_mac[0], s_interface_mac[1], s_interface_mac[2], 
        s_interface_mac[3], s_interface_mac[4], s_interface_mac[5]);
    fprintf(flog, "ifr_addr   =%s\n", inet_ntoa(s_interface_ip));
    fprintf(flog, "ifr_flags  =IFF_PROMISC\n");
    fprintf(flog, "pid        =0x%x\n", getpid());
    fprintf(flog, "header_eth =%d\n", HDR_LEN_ETH);
    fprintf(flog, "header_ip  =%d\n", HDR_LEN_IP);
    fprintf(flog, "\n");

    fd_at = open(AT_DEV, O_RDWR|O_NOCTTY);
    if(-1 == fd_at){
        fprintf(flog, "open at_dev error\n");
        exit(1);
    }
    fprintf(flog, "open %s,  fd: %d\n", AT_DEV, fd_at);

    fd_mux = open(MUX_DEV, O_RDWR|O_NOCTTY);
    if(-1 == fd_mux){
        fprintf(flog, "open mux_dev error\n");
        exit(1);
    }
    fprintf(flog, "open %s, fd: %d\n", MUX_DEV, fd_mux);

    pthread_t tid_socket_at_read, tid_socket_voice_read,tid_socket_data_read,tid_at_read, tid_mux_read, tid_socket_raw_read;
//at_read
    ret_val = pthread_create(&tid_at_read, NULL, at_read, NULL);
    if(ret_val != 0){
        fprintf(flog, "Fail to create thread at_read: %d \n", ret_val);
    }
//mux_read
    ret_val = pthread_create(&tid_mux_read, NULL, mux_read, NULL);
    if( ret_val != 0 ){
        fprintf(flog, "Fail to create thread mux_read: %d \n", ret_val);
    }
//socket_at_read
    if(pthread_create(&tid_socket_at_read,NULL,socket_at_read,NULL))
    {
        fprintf(flog, "pthread_create socket_read err\n");
    }
//socket_voice_read
	    if(pthread_create(&tid_socket_voice_read,NULL,socket_voice_read,NULL))
    {
        fprintf(flog, "pthread_create socket_read err\n");
    }
//socket_data_read
	    if(pthread_create(&tid_socket_data_read,NULL,socket_data_read,NULL))
    {
        fprintf(flog, "pthread_create socket_read err\n");
    }
//socket_raw_read
    if(pthread_create(&tid_socket_raw_read,NULL,socket_raw_read,NULL))
    {
        fprintf(flog, "pthread_create socket_read err\n");
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
            isSocketatReading = 0;
            isSocketvoiceReading = 0;
            isSocketdataReading = 0;
        }
        sleep(1);
    }
    close(st);
    fprintf(flog, "main thread exit.\n");
    return 0;
}
