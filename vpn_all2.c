#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
//#include <linux/in.h>
#include <linux/ip.h>
#include <net/if.h> 
#include <linux/icmp.h>
#include <errno.h>
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#define BUFFER_MAX 2048
#define ROUTE_INFO_MAX 20		/*max number of route item*/
#define ARP_SIZE_MAX 20			/*max number of arp item*/
#define DEVICE_MAX 10

struct arp_header{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    u_int16_t mac_type;
    
    u_int16_t hd_type;
    u_int16_t pro_type;
    u_int8_t hd_arrl;
    u_int8_t pro_arrl;
    u_int16_t arp_type;
    unsigned char arp_src_mac[6];
    in_addr_t src_ip;
    unsigned char arp_dst_mac[6];
    in_addr_t dst_ip;
    
    unsigned char unuse[18];
};
struct route_item{
    char destination[16];	//des_ip
    char gateway[16];		//gateway
    char netmask[16];		//netmask
    int interface;
}route_info[ROUTE_INFO_MAX];	
int route_item_index=0;			

struct arp_table_item{
    char ip_addr[16];		        //gateway IP
    unsigned char mac_addr[18];		//NEXT HOP MAC
}arp_table[ARP_SIZE_MAX];		
int arp_item_index=2;			

struct device_info{
    unsigned char mac[18];	        //LOCAL MAC
    char ip[16];
    char nextip[16];
    int interface;			//LOCAL INTERFACE
}device[DEVICE_MAX];		
int device_index=2;		

unsigned char pp[8];
unsigned char init_src_mac[6];
int init_dst_eth;
int sock_fd,sendsd, proto, n_read;
unsigned char buffer[BUFFER_MAX];
unsigned char *eth_head;
unsigned char *ip_head;
unsigned char *tcp_head;
unsigned char *udp_head;
unsigned char *icmp_head;
unsigned char *p;
char dst_ip[16];

void set_mac(unsigned char *mac,unsigned char p0,unsigned char p1,unsigned char p2,unsigned char p3,unsigned char p4,unsigned char p5){
    mac[0]=p0; mac[1]=p1; mac[2]=p2; mac[3]=p3; mac[4]=p4; mac[5]=p5;
}
int init(){
    strcpy(route_info[0].destination , "10.0.1.2"); 
    strcpy(route_info[0].gateway , "10.0.1.1");
    route_info[0].interface = 1;
    strcpy(route_info[1].destination , "10.0.0.2"); 
    strcpy(route_info[1].gateway , "192.168.0.2");
    route_info[1].interface = 0;
    route_item_index=2;
    
    strcpy(device[0].ip, "172.0.0.2");
    strcpy(device[0].nextip, "172.0.0.1");
    strcpy(device[1].ip, "10.0.1.1");
    strcpy(device[1].nextip, "10.0.1.2");
}
int init_arp(char *dest_ip){
    printf("init arp,eth:%d,destip:%s\n",init_dst_eth,dest_ip);
    if (init_dst_eth == 0 && strcmp(dest_ip,device[0].ip) == 0){
        strcpy(arp_table[0].ip_addr , device[0].ip);
        set_mac(arp_table[0].mac_addr,init_src_mac[0],init_src_mac[1],init_src_mac[2],init_src_mac[3],init_src_mac[4],init_src_mac[5]);
        printf("init arp1 - mac:%.2x:%02x:%02x:%02x:%02x:%02x\n",init_src_mac[0],init_src_mac[1],init_src_mac[2],init_src_mac[3],init_src_mac[4],init_src_mac[5]);
    }else if (init_dst_eth == 1 && strcmp(dest_ip,device[1].ip) == 0){
        strcpy(arp_table[1].ip_addr , device[1].ip);
        set_mac(arp_table[1].mac_addr,init_src_mac[0],init_src_mac[1],init_src_mac[2],init_src_mac[3],init_src_mac[4],init_src_mac[5]);
        printf("init arp2 - mac:%.2x:%02x:%02x:%02x:%02x:%02x\n",init_src_mac[0],init_src_mac[1],init_src_mac[2],init_src_mac[3],init_src_mac[4],init_src_mac[5]);
    }
}
int arp_convert_ip_to_hd(unsigned char *dst,unsigned char *dst_mac){
    int i;
    for(i=0; i<arp_item_index; i++) if (strcmp(dst,arp_table[i].ip_addr) == 0){
        memcpy(dst_mac,arp_table[i].mac_addr,6);
        return 0;
    }
    
    return 0;
}
int check_route_table(char *dest_ip){
    int i;
    for (i=0; i<route_item_index; i++) if (strcmp(route_info[i].destination,dest_ip) == 0) return i;
    return -1;
}
int get_eth_info(){
    struct ifreq ifr;
    
    char interface1[40] = "eth0";
    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface1);
    if (ioctl (sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
      perror ("ioctl() failed to get source MAC address ");
      return (EXIT_FAILURE);
    }
    memcpy (device[0].mac, ifr.ifr_hwaddr.sa_data, 6);
    device[0].interface = if_nametoindex (interface1);
    printf("MAC eth0: %.2x:%02x:%02x:%02x:%02x:%02x\n",device[0].mac[0],device[0].mac[1],device[0].mac[2],device[0].mac[3],device[0].mac[4],device[0].mac[5]);

    char interface2[40] = "eth1";
    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface2);
    if (ioctl (sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
      perror ("ioctl() failed to get source MAC address ");
      return (EXIT_FAILURE);
    }
    memcpy (device[1].mac, ifr.ifr_hwaddr.sa_data, 6);
    device[1].interface = if_nametoindex (interface2);
    printf("MAC eth1: %.2x:%02x:%02x:%02x:%02x:%02x\n",device[1].mac[0],device[1].mac[1],device[1].mac[2],device[1].mac[3],device[1].mac[4],device[1].mac[5]);
}
int islocal(unsigned char p0,unsigned char p1,unsigned char p2,unsigned char p3,unsigned char p4,unsigned char p5){
    int i;
    for (i = 0; i<device_index; i++) 
        if (p0 == device[i].mac[0] && p1 == device[i].mac[1] && p2 == device[i].mac[2] && p3 == device[i].mac[3] && p4 == device[i].mac[4] && p5 == device[i].mac[5]) return i;
    return -1;
}
int resend(int eth, char *dst, char* packet,int packet_size){

    unsigned char src_mac[6];
    unsigned char dst_mac[6];

    struct sockaddr_ll connection;
    memset (&connection, 0, sizeof (connection));
    arp_convert_ip_to_hd(dst,dst_mac);
    if (eth == 0){
        connection.sll_ifindex = device[0].interface;
        memcpy(src_mac,device[0].mac,6);
    }else{
        connection.sll_ifindex = device[1].interface;
        memcpy(src_mac,device[1].mac,6);
    }

    // Fill out sockaddr_ll.
    connection.sll_family = PF_PACKET;
    memcpy (connection.sll_addr, dst_mac, 6);
    connection.sll_halen = htons (6);
    printf("next eth:eth%d-%d\n",eth,connection.sll_ifindex);
    printf("next MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",connection.sll_addr[0],connection.sll_addr[1],connection.sll_addr[2],connection.sll_addr[3],connection.sll_addr[4],connection.sll_addr[5]);
    
    // Destination and Source MAC addresses
    memcpy (packet, dst_mac, 6);
    memcpy (packet + 6, src_mac, 6);
    unsigned char *p = packet;
    printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x==> %.2x:%02x:%02x:%02x:%02x:%02x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
    if ((p[12]<<8)+p[13] == 0x0800) printf("is ip\n"); else printf("not ip%04x\n",(p[12]<<8)+p[13]);
    p = packet + 14+12;
    printf("--IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
    //Sendto
    int nn;
    if((nn=sendto(sock_fd,packet,packet_size,0,(struct sockaddr *)&connection,sizeof(connection)))<0){
        printf("sendto error:%d\n",errno);
        exit(-1);
    }else{
        printf("send %d OK\n",nn);
    }
}

unsigned short CheckSum(unsigned short *buffer, int size)  
{  
    unsigned int cksum=0;  
    while (size > 1)   
    {  
        cksum += *buffer++;  
        size -= sizeof(unsigned short);  
    }  
    if (size)   
    {  
        cksum += *(unsigned short*)buffer;  
    }  
    /*对每个16bit进行二进制反码求和*/  
    cksum = (cksum >> 16) + (cksum & 0xffff);  
    cksum += (cksum >>16);  
    return (unsigned short)(~cksum);  
}  

int unpack_packet(char* buffer,int buffer_len,char* error_info){
    printf("vpn unpack\n");
    char dst_ip[16];
    char* iphead = buffer + sizeof(struct iphdr);
    char* p = iphead + 12;
    sprintf(dst_ip,"%d.%d.%d.%d",p[4],p[5],p[6],p[7]);
        
    int index = check_route_table(dst_ip);
    if (index < 0 ) return -1;
    

    char packet[14 + buffer_len - sizeof(struct iphdr)];
    
    packet[12] = 0x08;
    packet[13] = 0x00;
    char *ip =  packet + 14;
    
    memcpy(ip,buffer+sizeof(struct iphdr),buffer_len-sizeof(struct iphdr));
    
    resend(1,device[1].ip,packet,14 + buffer_len - sizeof(struct iphdr));
}

int repack_packet(char* buffer,int buffer_len,char* error_info,char* dst_ip){
    /*
    struct iphdr* ipp = (struct iphdr*)buffer;
    memset((char*)ipp->check,0,sizeof(ipp->check));
    ipp->check = CheckSum((unsigned short*)ipp,sizeof(struct iphdr)); 
    */

    int index = check_route_table(dst_ip);
    if (index < 0 ) return -1;
    printf("index:%d\n",index);
    struct iphdr* ip;
    unsigned char packet[14 + sizeof(struct iphdr) + buffer_len];

    packet[12] = 0x08;
    packet[13] = 0x00;
    
    ip = (struct iphdr*) (packet + 14);
    unsigned char* data = packet + 14 + sizeof(struct iphdr);
    
    //IP
    memset(ip,0,sizeof(struct iphdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + buffer_len;
    ip->id = 0;
    ip->ttl = 63;
    ip->protocol = IPPROTO_IP;
    ip->saddr = inet_addr(device[0].ip);               //source ip
    ip->daddr = inet_addr(route_info[index].gateway);  //dest ip
    ip->check = CheckSum((unsigned short *)ip,sizeof(struct iphdr));
    printf("checksum:%04x\n",ip->check);
    memcpy(data,buffer,buffer_len);
    printf("vpn repack\n");
    init_send_send(buffer,buffer_len,device[0].ip,route_info[index].gateway);
    //resend(1,device[1].ip,packet,14 + sizeof(struct iphdr) + buffer_len);
}

int start_receive(){
    while(1){
        n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
        eth_head = buffer;
        p = eth_head;
        int flag = 0;
        printf("-------------------Receive Of A Package of size:%d---------------------\n",n_read);
        printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x==> %.2x:%02x:%02x:%02x:%02x:%02x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
        set_mac(init_src_mac,p[6],p[7],p[8],p[9],p[10],p[11]);
        if ((init_dst_eth = islocal(p[0],p[1],p[2],p[3],p[4],p[5])) < 0) flag = 1; 
        switch((p[12]<<8)+p[13]){
            case 0x0800: printf("IP Header: \n"); goto Net_IP; break;
            case 0x0806: printf("ARP- Address Resolution Protocol \n"); goto Net_ARP; break;
            case 0x0808: printf("ARP- Frame Relay ARP[RFC1701] \n"); goto End; break;
            case 0x8035: printf("RARP \n"); goto Net_RARP; break;
            case 0x8100: printf("Ethernet Automatic Protection Switching \n"); goto Net_RARP; break;
            case 0x8137: printf("Internet Packet Exchange \n"); goto Net_RARP; break;
            case 0x86DD: printf("Internet Protocol version 6 \n"); goto Net_RARP; break;
            case 0x880B: printf("Point-to-Point Protocol \n"); goto Net_RARP; break;
            default: printf("do not support,%04x\n",(p[12]<<8)+p[13]);;
        }
    Net_ARP:;
        unsigned char *arp = eth_head+14;
        sprintf(dst_ip,"%d.%d.%d.%d",arp[24],arp[25],arp[26],arp[27]);
        //printf("Net_ARP:%d.%d.%d.%d\n",arp[24],arp[25],arp[26],arp[27]);
        init_arp(dst_ip);
    goto End;
    Net_IP:;
        ip_head = eth_head+14;
        p = ip_head+12;
        sprintf(dst_ip,"%d.%d.%d.%d",p[4],p[5],p[6],p[7]);
        printf("--IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
        
        if (init_dst_eth == 1) repack_packet(ip_head,n_read-14,0,dst_ip);
        if (init_dst_eth == 0) unpack_packet(ip_head,n_read-14,0);

        goto End;
    Net_RARP:;
        goto End;
    End:;
    }
    return -1;
}

int init_send(){
    printf("init send\n");
    //create ethernet header
    unsigned char broadcast[6];
    //unsigned char zeromac[6];
    set_mac(broadcast,0xff,0xff,0xff,0xff,0xff,0xff);
    //set_mac(zeromac,0x00,0x00,0x00,0x00,0x00,0x00);
    char packet[sizeof(struct arp_header)];
    struct arp_header* arp = packet;

    //send1
    memcpy(arp->dst_mac,broadcast,6);
    memcpy(arp->src_mac,device[0].mac,6);
    arp->mac_type = htons(0x0806);
    arp->hd_type = htons(ARPHRD_ETHER);
    arp->pro_type = htons(ETHERTYPE_IP);
    arp->hd_arrl = ETH_ALEN;
    arp->pro_arrl = 4;
    arp->arp_type = htons(ARPOP_REQUEST);
    memcpy(arp->arp_src_mac,device[0].mac,6);
    
    arp->src_ip = inet_addr(device[0].ip);
    memcpy(arp->arp_dst_mac,device[0].mac,6);
    arp->dst_ip = inet_addr(device[0].nextip);

    unsigned char *ar = packet+14;
    //这里不懂为什么，通过打印发现最后的这个ip向后偏移了两个字节，通过前移2个字节才成功
    ar[24] = ar[26]; ar[25] = ar[27]; ar[26] =ar[28]; ar[27] = ar[29];
/*
    printf("hd_type:%d,pro_type:%d,len1:%d,len2:%d\n",(ar[0]<<8)+ar[1],(ar[2]<<8)+ar[3],ar[4],ar[5]);
    printf("arp type:%d\n",(ar[6]<<8)+ar[7]);
    printf("srcmac: %.2x:%02x:%02x:%02x:%02x:%02x\n",ar[8],ar[9],ar[10],ar[11],ar[12],ar[13]);
    printf("srcip:%d.%d.%d.%d\n",ar[14],ar[15],ar[16],ar[17]);
    printf("dstmac: %.2x:%02x:%02x:%02x:%02x:%02x\n",ar[18],ar[19],ar[20],ar[21],ar[22],ar[23]);
    printf("dstip:%d.%d.%d.%d\n",ar[24],ar[25],ar[26],ar[27]);
*/

    //connection
    struct sockaddr_ll connection;
    memset (&connection, 0, sizeof (connection));
    connection.sll_ifindex = device[0].interface;
    connection.sll_family = PF_PACKET;
    memcpy (connection.sll_addr, broadcast, 6);
    connection.sll_halen = htons (6);

    int nn;
    if((nn=sendto(sock_fd,packet,sizeof(struct arp_header),0,(struct sockaddr *)&connection,sizeof(connection)))<0){
        printf("sendto error:%d\n",errno);
        exit(-1);
    }else{
        printf("arp send %d OK\n",nn);
    }


    //send2
    memcpy(arp->dst_mac,broadcast,6);
    memcpy(arp->src_mac,device[1].mac,6);
    arp->mac_type = htons(0x0806);
    arp->hd_type = htons(ARPHRD_ETHER);
    arp->pro_type = htons(ETHERTYPE_IP);
    arp->hd_arrl = ETH_ALEN;
    arp->pro_arrl = 4;
    arp->arp_type = htons(ARPOP_REQUEST);
    memcpy(arp->arp_src_mac,device[1].mac,6);
    
    arp->src_ip = inet_addr(device[1].ip);
    memcpy(arp->arp_dst_mac,device[1].mac,6);
    arp->dst_ip = inet_addr(device[1].nextip);

    ar = packet+14;
    //
    ar[24] = ar[26]; ar[25] = ar[27]; ar[26] =ar[28]; ar[27] = ar[29];
    /*
    printf("hd_type:%d,pro_type:%d,len1:%d,len2:%d\n",(ar[0]<<8)+ar[1],(ar[2]<<8)+ar[3],ar[4],ar[5]);
    printf("arp type:%d\n",(ar[6]<<8)+ar[7]);
    printf("srcmac: %.2x:%02x:%02x:%02x:%02x:%02x\n",ar[8],ar[9],ar[10],ar[11],ar[12],ar[13]);
    printf("srcip:%d.%d.%d.%d\n",ar[14],ar[15],ar[16],ar[17]);
    printf("dstmac: %.2x:%02x:%02x:%02x:%02x:%02x\n",ar[18],ar[19],ar[20],ar[21],ar[22],ar[23]);
    printf("dstip:%d.%d.%d.%d\n",ar[24],ar[25],ar[26],ar[27]);
    */
    //connection
    memset (&connection, 0, sizeof (connection));
    connection.sll_ifindex = device[1].interface;
    connection.sll_family = PF_PACKET;
    memcpy (connection.sll_addr, broadcast, 6);
    connection.sll_halen = htons (6);


    if((nn=sendto(sock_fd,packet,sizeof(struct arp_header),0,(struct sockaddr *)&connection,sizeof(connection)))<0){
        printf("sendto error:%d\n",errno);
        exit(-1);
    }else{
        printf("arp send %d OK\n",nn);
    }


}

int init_send_send(char* buffer,int buffer_len,char* srcip,char* dstip){

    struct sockaddr_in connection;

    unsigned char packet[sizeof(struct iphdr) + buffer_len];
    struct iphdr *ip = (struct iphdr*) packet;
    memcpy(packet+sizeof(struct iphdr),buffer,buffer_len);
 
    //IP
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) +buffer_len;
    ip->id = 0;
    ip->ttl = 63;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr(srcip);  //source ip
    ip->daddr = inet_addr(dstip);  //dest ip
 
 
    //目标IP
    connection.sin_family = AF_INET;
    connection.sin_addr.s_addr = inet_addr(dstip);
 
    //Sendto
    int nn;
    if((nn = sendto(sendsd, packet, ip->tot_len, 0,(struct sockaddr *)&connection, sizeof(struct sockaddr))) < 0){
        printf("sendto error!%d",errno);
        exit(-1);
    }else{
        printf("send %d OK\n",nn);
    }
}

int main(int argc,char* argv[]){
    if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        printf("error create raw socket\n");
        return -1;
    }else printf("create raw socket successfully\n");

    sendsd = socket(AF_INET,SOCK_RAW,htons(ETH_P_ALL));
    int on = 1;
    if(setsockopt(sendsd,IPPROTO_IP,IP_HDRINCL,&on, sizeof(on)) < 0) printf("setsockopt error\n");
    if (sendsd < 0){
        printf("create send raw socket error! ");
        return 0;
    }else printf("create send raw socket successfully\n");


    get_eth_info();  
    init();
    getchar();    
    init_send();

    start_receive();
    return -1;
}