#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void createTCPPacket ( unsigned char *buf ) {

	struct ip6_hdr *iphdr = (struct ip6_hdr *) buf;
	struct tcphdr *tcphdr = (struct tcphdr *)(buf + sizeof (struct ip6_hdr));
	unsigned char *data = buf + sizeof (struct tcphdr) + sizeof (struct ip6_hdr);
	//strcpy (data, "asdf");
	int tcp_flags [8];

	//unsigned short iphdrlen;

	//struct iphdr *iph = (struct iphdr *)buf;
	//iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(buf + sizeof (struct ip6_hdr));

	char input [32];

	iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;	//change protocol to tcp
	//memset( buf + sizeof ( struct iphdr ), 0, iph -> tot_len );	//clean data field to save icmp packet
		//calculate total length
	//iph -> tot_len = 28;



	printf ("\nTCP source (1234): ");
		fgets (input, 32, stdin);
			if (atoi(input)== 0)
				tcph->th_sport = htons (1234);	//TCP source
			else
				tcph->th_sport = htons (atoi (input));
	printf ("\nTCP destination port (4321): ");
		fgets (input, 32, stdin);
			if (atoi(input)== 0)
				tcph->th_dport = htons (4321);	//TCP destination
			else
				tcph->th_dport = htons (atoi (input));

	printf ("\nTCP sequence number (0): ");
		fgets (input, 32, stdin);
			if (atoi(input)== 0)
				tcph->th_seq = 0;	//TCP sequence
			else
				tcph->th_seq = atoi (input);
	printf("\nTCP ACK (0);");
		fgets(input, 32, stdin);
			if (atoi(input)== 0)
				tcph->th_ack = 0;	//TCP ack
			else
				tcph->th_ack = atoi (input);
				printf("\nTCP off (5);");
					fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcph->th_off = 5;	//TCP off
						else
							tcph->th_off = atoi (input);
			    printf("\nTCP win (0);");
					fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcph->th_win = htons (65535);	//TCP win
						else
							tcph->th_win = atoi (input);

				printf("\nTCP urp (0);");
					fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcph->th_urp = 0;	//TCP urp
						else
							tcph->th_urp = atoi (input);

						  // Flags (8 bits)
						printf ("FLAGS: \n");
						printf("FIN (0):");
						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [0] = 0;
						else
							tcp_flags [0] = 1;
						printf("SYN (0):");

						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [1] = 0;
						else
							tcp_flags [1] = 1;

						printf("RST (0):");
						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [2] = 0;
						else
							tcp_flags [2] = 1;
						printf("PSH (0):");

						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [3] = 0;
						else
							tcp_flags [3] = 1;

						printf("ACK (0):");
						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [4] = 0;
						else
							tcp_flags [4] = 1;
						printf("URG (0):");

						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [5] = 0;
						else
							tcp_flags [5] = 1;

						printf("ECE (0):");
						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [6] = 0;
						else
							tcp_flags [6] = 1;
						printf("CWR (0):");

						fgets(input, 32, stdin);
						if (atoi(input)== 0)
							tcp_flags [7] = 0;
						else
							tcp_flags [7] = 1;

						  tcphdr->th_flags = 0;
						  for (int i=0; i<8; i++) {
						    tcphdr->th_flags += (tcp_flags[i] << i);
						  }


						  printf ("DATA: ");
						  fgets(input, 32, stdin);
						  	  memcpy(data, input, strlen (input)-1);




iphdr->ip6_ctlun.ip6_un1.ip6_un1_plen = htons ( sizeof (struct tcphdr) + strlen (data));

}



