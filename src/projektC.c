/*
 ============================================================================
 Name        : projektC.c
 Author      :
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include "program_lib.h"
#include <dlfcn.h>
#include <netinet/in.h>
#include <netinet/ip6.h>



int main (void) {

	void * Ipv6_lib = malloc(sizeof (void));
	void * Tcp_lib = malloc(sizeof (void));

	char input [32];
	int *count = malloc (sizeof (int));
	struct ip6_hdr *iphdr;
	unsigned char *datagram;
	unsigned char * (*ipv6) () = malloc (sizeof (unsigned short *));
	void (*tcp) (unsigned char *) = malloc (sizeof (void));

	datagram = malloc (sizeof (unsigned char *));


	Ipv6_lib = LoadIpv6();

	ipv6 = dlsym(Ipv6_lib, "CreateIPV6Packet");
	datagram = (*ipv6)();
	iphdr = (struct ip6_hdr *) datagram;
	if ( iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
		Tcp_lib = LoadTCP();
		tcp = dlsym(Tcp_lib, "createTCPPacket");
		(*tcp) (datagram);
	}

	printf ("How many packets do you want to send?");
	fgets (input, 32, stdin);
	*count = atoi(input);

	LoadToList( count, datagram );


	SendPacket(datagram);
	EXIT_SUCCESS;
}
