

#ifndef PROGRAM_LIB_H_
#define PROGRAM_LIB_H_

//linked list struct
struct Node {
	int id;
	unsigned char *datagram;
	struct Node *next;
	struct Node *prev;
};


void * LoadIpv6 ();	//function declaration to load IPv4 library
void * LoadTCP ();	//function declaration to load ICMP library

void SendPacket (unsigned char *interface );	//function to send packet from linked list
void LoadToList ( int *count, unsigned char *dtgr );	//function to load data to list

struct Node *ReserveMem ( unsigned char *datagram );	//function to reserve memory for new list element
void InsertTail ( unsigned char *datagram );	//function to put new element at the end of the list
void PrintList ();	//function to print linked list
void DeleteList ();	//function to delete linked list
struct Node * ReturnHead (); //function to return head of the list

#endif /* PROGRAM_LIB_H_ */
