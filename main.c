#include <unistd.h>             // close
#include<stdio.h>
#include<stdlib.h>              // malloc
#include<netinet/ip_icmp.h>     // ICMP header
#include<netinet/udp.h>         // UDP header
#include<netinet/tcp.h>         // TCP header
#include<sys/socket.h>
#include<arpa/inet.h>           // in_addr, htons
#include<netinet/if_ether.h>    // ETH_P_ALL
#include<netinet/ip.h>	        // iphdr

// Sorry for the long printf's

// Dumps and prints the contents of the rest of the packet (past its header)
// The buffer is offset upon calling the function
void dump_data(unsigned char *buffer, int bufsize) {
    printf("\nContents:\n");
    // In hex
    for (int i = 0; i < bufsize; ++i) {
        printf("%02X ", buffer[i]);
        
        if (i != 0 && (i+1) % 4 == 0) {
            printf("\n");
        }
    }
    
    printf("\n\n");
    // In ASCII
    for (int i = 0; i < bufsize; ++i) {
        if(buffer[i]>=32 && buffer[i]<=128) { // If the value is in the ASCII table
            printf("%c ", buffer[i]);
        } else {
            printf(".");
        }
        
        if (i != 0 && (i+1) % 8 == 0) {
            printf("\n");
        }
    }
    
    printf("\n");
}


void print_icmp_packet(unsigned char *buffer, int ip_header_size, int bytes_read) {  
    struct icmphdr *icmphdr = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + ip_header_size); // Ethernet header and IP header sizes as offsets
    // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
    printf("Type : %d , Code : %d , Checksum : %d\n\n", icmphdr->type, icmphdr->code, icmphdr->checksum);
    
    int offset = sizeof(struct ethhdr) + ip_header_size + sizeof(struct icmphdr);
    dump_data(buffer + offset, bytes_read - offset);
}


void print_tcp_packet(unsigned char *buffer, int ip_header_size, int bytes_read) {
    struct tcphdr *tcphdr = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header_size); // Ethernet header and IP header sizes as offsets
    // ntohs changes from the network's byte ordering to the host's
    printf("Src. port: %d, Dest. port : %d , Seq. no. : %d ,\nAck no: %d , Window size : %d , Urgent pointer (last urgent data byte) : %d\n", 
           ntohs(tcphdr->source), ntohs(tcphdr->dest), ntohs(tcphdr->seq), 
           ntohs(tcphdr->ack_seq), ntohs(tcphdr->window), tcphdr->urg_ptr);
    
    printf("\nFlags:\n");
    /*    
     * https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
     * 
     * NS (1 bit): ECN-nonce - concealment protection
     * CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host
     * to indicate that it received a TCP segment with the ECE flag set and had 
     * responded in congestion control mechanism.
     * 
     * ECE (1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
     * 
     *      If the SYN flag is set (1), that the TCP peer is ECN capable.
     *      
     *      If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in the IP header was received during normal transmission.
     *      This serves as an indication of network congestion (or impending congestion) to the TCP sender.
     * 
     * URG (1 bit): Indicates that the Urgent pointer field is significant
     * ACK (1 bit): Indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set.
     * PSH (1 bit): Push function. Asks to push the buffered data to the receiving application.
     * RST (1 bit): Reset the connection
     * SYN (1 bit): Synchronize sequence numbers. Only the first packet sent from each end should have this flag set. 
     * Some other flags and fields change meaning based on this flag, and some are only valid when it is set, and others when it is clear.
     * FIN (1 bit): Last packet from sender
     */
    printf("URG : %d , ACK : %d , PSH : %d ,\nRST : %d , SYN : %d, FIN : %d\n", tcphdr->urg, tcphdr->ack, tcphdr->psh, tcphdr->rst, tcphdr->syn, tcphdr->fin);
    
    int offset = sizeof(struct ethhdr) + ip_header_size + sizeof(struct tcphdr);
    dump_data(buffer + offset, bytes_read - offset);
}


void print_udp_packet(unsigned char *buffer, int ip_header_size, int bytes_read) {
    struct udphdr *udphdr = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header_size); // Ethernet header and IP header sizes as offsets
    
    printf("Src. port: %d, Dest. port : %d ,\nLength : %d, Checksum : %04x\n", ntohs(udphdr->source), ntohs(udphdr->dest), ntohs(udphdr->len), ntohs(udphdr->check));
    
    int offset = sizeof(struct ethhdr) + ip_header_size + sizeof(struct udphdr);
    dump_data(buffer + offset, bytes_read - offset);
}


void perform_surgery(unsigned char *buffer, int bytes_read) {
    // Internal kernel structs for an ethernet frame and an IP packet
    
    // Ethernet frame: Preable + Start frame delimiter + Dest. MAC + Src. MAC + VLAN Tag + Length + Payload + CRC + Interpacket gap
    struct ethhdr *ethhdr = (struct ethhdr*)(buffer);

    // IP packet: Version + header length (due to the options field) + Diff. services code point + Explicit congestion notification + 
    // Packet length + IP datagram fragment ID + Flags + Fragment offset +
    // TTL + IP Protocol number + Header checksum + 
    // Src. address + Dest. address + (optional) options field
    struct iphdr *iphdr = (struct iphdr*)(buffer + sizeof(struct ethhdr)); // Skips the ethernet header from the frame and goes directly to the payload (IP packet)
    
    printf("\n\n---------------------------------\n");
    
    printf("Ethernet frame information:\n");
    
    printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x , Dest. MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        (unsigned char) ethhdr->h_source[0],
        (unsigned char) ethhdr->h_source[1],
        (unsigned char) ethhdr->h_source[2],
        (unsigned char) ethhdr->h_source[3],
        (unsigned char) ethhdr->h_source[4],
        (unsigned char) ethhdr->h_source[5],
        (unsigned char) ethhdr->h_dest[0],
        (unsigned char) ethhdr->h_dest[1],
        (unsigned char) ethhdr->h_dest[2],
        (unsigned char) ethhdr->h_dest[3],
        (unsigned char) ethhdr->h_dest[4],
        (unsigned char) ethhdr->h_dest[5]);
    
    printf("\nIP header information:\n");
    
    // In order to print the source and destination addresses
    struct sockaddr_in source_addr , dest_addr;
	source_addr.sin_addr.s_addr = iphdr->saddr;
    dest_addr.sin_addr.s_addr = iphdr->daddr;
    
    // The header length is how many 4-bytes groups are in there
    printf("Version : %d , Header length : %d , DSCP : %02x , Packet length : %d\nDatagram ID : %d , Fragment offset : %d , TTL : %d , IP protocol no. : %d\nChecksum : %04x  ,\nSrc addr. : %s , Dest addr. : %s\n\n", 
           iphdr->version, iphdr->ihl*4, iphdr->tos, iphdr->tot_len, 
           iphdr->id, iphdr->frag_off, iphdr->ttl, iphdr->protocol, 
           iphdr->check, inet_ntoa(source_addr.sin_addr), inet_ntoa(dest_addr.sin_addr));
    
    
    switch (iphdr->protocol) {
		case 1:  // ICMP Protocol
            printf("\nICMP packet:\n");
			print_icmp_packet(buffer, iphdr->ihl*4, bytes_read);
			break;
        case 2:
            printf("\nIGMP packet\n");
		case 6:  // TCP Protocol
            printf("\nTCP packet:\n");
			print_tcp_packet(buffer , iphdr->ihl*4, bytes_read);
			break;
		case 17: // UDP Protocol
            printf("\nUDP packet:\n");
			print_udp_packet(buffer , iphdr->ihl*4, bytes_read);
			break;
        case 41:
            printf("\nipv6 ENCAP packet\n");
        case 89:
            printf("\nOSPF packet\n");
        case 132:
            printf("\nSCTP packet\n");
        default: // Others
            printf("\nOther protocol, number: %02x\n", iphdr->protocol);
			break;
	}
	printf("---------------------------------\n");
}


int main() {
    socklen_t src_addr_size;
	struct sockaddr src_addr;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); // 64 KiB, max theoretical frame size for a IP packet
    
    // Create a raw socket
    // AF_PACKET: Low-level packet interface domain (captures incoming and outgoing by cloning them)
    // SOCK_RAW: raw type
    // htons(ETH_P_ALL) : Capture every packet (of whatever protocol)
    int raw_socket = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    if (raw_socket < 0) {
        printf("Error when creating the raw socket, maybe you are not executing as root?\n");
        exit(-1);
    }
    
    while(1) {
        // Receive data from the socket. Since it is a raw socket, it will receive all incoming packets
        // recvfrom will fill out the source address on src_addr if possible.
        
        // addrlen is a value-result argument, which the caller should initialize before the call to the 
        // size of the buffer associated with src_addr
        src_addr_size = sizeof src_addr;
        
        int bytes_read = recvfrom(raw_socket , buffer , 65536 , 0 , &src_addr , &src_addr_size);
        if (raw_socket < 0) {
            printf("Error when receiving a packet\n");
            exit(-1);
        }
        
        perform_surgery(buffer, bytes_read);
    }
    
    close(raw_socket);
    free(buffer);
    return 0;
}
