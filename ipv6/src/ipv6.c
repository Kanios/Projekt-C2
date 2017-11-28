
#include <stdio.h>
#include <stdlib.h>
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_UDP, INET6_ADDRSTRLEN
#include <netinet/ip6.h>      // struct ip6_hdr






unsigned char * CreateIPV6Packet (){

	unsigned char *datagram = malloc (4096);
	struct ip6_hdr *iphdr = (struct ip6_hdr *) datagram;
	char input [32];

	printf ("Version set to default (6)\n");
	iphdr->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl ((6 << 28) | (0 << 20) | 0);

	printf ("Hop limit: (255): ");
	fgets (input, 32, stdin);
	if (atoi(input)== 0)
		iphdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;
	else
		iphdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = atoi (input);

	printf ("Checksum will be calculated\n");

	printf ("Type protocol:\n[0:IPv6] [1:TCP]: ");
	fgets (input, 32, stdin);
	if (atoi(input)== 0)
		iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_RAW;
	else
		iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;

	if (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_RAW){
		printf ("Type msg to send: ");
		fgets (input, 32, stdin);
		strcpy((char*)datagram+sizeof(struct ip6_hdr), input);
	}

	iphdr->ip6_ctlun.ip6_un1.ip6_un1_plen = htons((short)strlen(input)-1);



	return datagram;
}

