#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

void usage(){
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");	
}

typedef struct libnet_ethernet_hdr{
   u_int8_t dstmac[6]; 
   u_int8_t srcmac[6];
   u_int16_t type;
}Ethernet_Header;

typedef struct libnet_ip_hdr{
	uint8_t length:4, version:4;
	u_int8_t TypeofSource;
	u_int16_t totallength;
	u_int8_t Trash[8];
	u_int8_t src_addr[4];
	u_int8_t dst_addr[4];
}IP_Header;

typedef struct libnet_tcp_hdr{
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int8_t Trash[8];
	u_int8_t off:4,length:4;
}TCP_Header;

typedef struct Datai_file{
	u_int8_t data[16];
}Data;

void print_Ethernet_Header(const u_char* packet){
	Ethernet_Header *Header;
	Header = (Ethernet_Header*)packet;
	printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",Header->srcmac[0],Header->srcmac[1],Header->srcmac[2],Header->srcmac[3],Header->srcmac[4],Header->srcmac[5]);
	printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
}

void print_IP_Header(const u_char* packet){
	IP_Header *Header;
	Header = (IP_Header*)packet;
	printf("src ip : %d.%d.%d.%d\n", Header->src_addr[0],Header->src_addr[1],Header->src_addr[2],Header->src_addr[3]);
	printf("src ip : %d.%d.%d.%d\n", Header->dst_addr[0],Header->dst_addr[1],Header->dst_addr[2],Header->dst_addr[3]);

}

void print_TCP_Header(const u_char* packet){
	TCP_Header *Header;
	Header = (TCP_Header*)packet;
	printf("src Port: %u\n", ntohs(Header->src_port));
	printf("dst Port: %u\n", ntohs(Header->dst_port));
}

void print_Data(const u_char* packet){
	Data *Header;
	Header = (Data*)packet;
	printf("DATA : ");
	for(int i=0; i<16; i++){
		printf("%02x",Header->data[i]);
	}
	printf("\n\n");
}

int main(int argc, char* argv[]){
	if(argc != 2){
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr){
		fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		return -1;
	}

	while (true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res==-2){
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		print_Ethernet_Header(packet);
		packet+=14;
		print_IP_Header(packet);
		IP_Header *tmp;
		tmp = (IP_Header*)packet;
		packet+=(u_int16_t)(tmp->length)*4;
		print_TCP_Header(packet);
		TCP_Header *tmp1;
		tmp1 = (TCP_Header*)packet;
		packet+=(u_int16_t)(tmp1->length)*4;
		print_Data(packet);
	}

	pcap_close(handle);
}







