struct ipTableEntry {

  u_char dest_ip[4];
  char mask;
  u_char next_hop[4];
  u_char mac[6];
  char interface[8];

};



void insertTable(struct ipTableEntry* ,char* ,char ,char* ,u_char* ,char *); 
/*insert(struct ipTableEntry* ipte, char* dest_ip, char mask, char* next_hop, u_char* mac, char *interface)*/
/*ipte points to the tableEntry needed to be inserted or modified*/
/*desp_ip, next_hop, and interface are passed as strings, pass NULL if no change is needed*/
/*mask is passed as a number, but stored in a char; pass -1 if no change is needed*/

u_char* find_next_ip(struct ipTableEntry [], char *, char, int);


u_char* find_mac(struct ipTableEntry [], char *, char, int );
/*1st arg: the pointer to the ipTableEntry array*/
/*2nd arg: ip string*/
/*3rd arg: mask number*/
/*4th arg: size of the ipTableEntry array*/


void printTable(struct ipTableEntry [], int );
