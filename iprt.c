#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "iprt.h"

/*
int main() {
  
  struct ipTableEntry ipTable[5];

  
  u_char mac[6];
  memset(mac, 0xFF, 6);


  insert(&ipTable[0], "10.2.159.0", 24, "2.2.2.2", mac, "eth0");
  u_char* nip = find_next_ip(ipTable, "10.2.159.0", 24, 1);
  //if(nip != NULL)
  //printf("%d.%d.%d.%d\n", nip[0], nip[1], nip[2], nip[3]);

  u_char* mc = find_mac(ipTable, "10.2.159.0", 24, 1);
  //if(mc != NULL)
  //printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mc[0], mc[1], mc[2], mc[3], mc[4], mc[5]);

  printTable(ipTable, 1);

  return 0;
}

*/

void insertTable(struct ipTableEntry* ipte, char* dest_ip, char mask, char* next_hop, u_char* mac, char *interface) {
  
  
  char buf[20];
  char *pch = NULL;
  char *cptr = buf;

  if(mask != -1)
    ipte->mask = mask;

  if(dest_ip != NULL) {

    strcpy(buf, dest_ip);
    
    pch = strchr(buf, '.');
    *pch++ = '\0';
    ipte->dest_ip[0] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    ipte->dest_ip[1] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    ipte->dest_ip[2] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '\0');
    ipte->dest_ip[3] = atoi(cptr);
    
    //printf("%d.%d.%d.%d\n", ipte->dest_ip[0], ipte->dest_ip[1], ipte->dest_ip[2], ipte->dest_ip[3]);

  }

  if(next_hop != NULL) {

    strcpy(buf, next_hop);

    pch = NULL;
    cptr = buf;
  
    pch = strchr(buf, '.');
    *pch++ = '\0';
    ipte->next_hop[0] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    ipte->next_hop[1] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    ipte->next_hop[2] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '\0');
    ipte->next_hop[3] = atoi(cptr);
    
    //printf("%d.%d.%d.%d\n", ipte->next_hop[0], ipte->next_hop[1], ipte->next_hop[2], ipte->next_hop[3]);
  }
  
  if(mac != NULL) {
    memcpy(ipte->mac, mac, 6);
    /*
    int i=0;
    for(i=0; i<6; i++) {
      printf("%02X:", ipte->mac[i]);
    }
    printf("\n");
    */
  }

  if(interface != NULL)
    strcpy(ipte->interface, interface);
  //printf("%s\n", ipte->interface);

  //printf("mask:%d\n", ipte->mask);

}

u_char* find_next_ip(struct ipTableEntry ipte[], char *dest_ip, char mask, int size) {
  
  char buf[20];
  char *pch = NULL;
  char *cptr = buf;
  u_char target[4];

  if(dest_ip != NULL) {

    strcpy(buf, dest_ip);
    
    pch = strchr(buf, '.');
    *pch++ = '\0';
    target[0] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    target[1] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    target[2] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '\0');
    target[3] = atoi(cptr);
    
    //printf("%d.%d.%d.%d\n", ipte->dest_ip[0], ipte->dest_ip[1], ipte->dest_ip[2], ipte->dest_ip[3]);

  }


  int i=0;

  for(i=0; i<size; i++) {

    if(!memcmp(ipte[i].dest_ip, target, 4) && ipte[i].mask == mask)
      return ipte[i].dest_ip;
  }

  //printf("good\n");

  return NULL;
}


u_char* find_mac(struct ipTableEntry ipte[], char *dest_ip, char mask, int size) {
  
  char buf[20];
  char *pch = NULL;
  char *cptr = buf;
  u_char target[4];

  if(dest_ip != NULL) {

    strcpy(buf, dest_ip);
    
    pch = strchr(buf, '.');
    *pch++ = '\0';
    target[0] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    target[1] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '.');
    *pch++ = '\0';
    target[2] = atoi(cptr);
    
    cptr = pch;
    pch = strchr(pch, '\0');
    target[3] = atoi(cptr);
    
    //printf("%d.%d.%d.%d\n", ipte->dest_ip[0], ipte->dest_ip[1], ipte->dest_ip[2], ipte->dest_ip[3]);

  }

  int i=0;

  for(i=0; i<size; i++) {

    if(!memcmp(ipte[i].dest_ip, target, 4) && ipte[i].mask == mask)
      return ipte[i].mac;
  }

  //printf("good\n");

  return NULL;
  
}

void printTable(struct ipTableEntry ipte[], int size) {

  printf("Destination\t");
  printf("NextHop         ");
  printf("Mask           ");
  printf("MAC              ");
  printf("Iface\n");
  
  int i=0;
  for(i=0; i<size; i++) {
    
    printf("%d.%d.%d.%d", 
	   ipte[i].dest_ip[0], 
	   ipte[i].dest_ip[1],
	   ipte[i].dest_ip[2],
	   ipte[i].dest_ip[3]);

    printf("\t");

    printf("%d.%d.%d.%d",
	   ipte[i].next_hop[0], 
	   ipte[i].next_hop[1],
	   ipte[i].next_hop[2],
	   ipte[i].next_hop[3]);
    
    printf("\t");

    printf("\\%d", ipte[i].mask);

    printf("\t");

    printf("%02X:%02X:%02X:%02X:%02X:%02X",
	   ipte[i].mac[0], 
	   ipte[i].mac[1],
	   ipte[i].mac[2],
	   ipte[i].mac[3],
	   ipte[i].mac[4],
	   ipte[i].mac[5]);
    
    printf("\t");
    
    printf("%s\n", ipte[i].interface);
  }

}
