/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


void sr_handleIPPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  printf("handleIPPacket \n");
  /*if(isIMCP)
  {
    //fill in code to handle IMCP stuff
  }
  else
  {
    //fill in code to handle regular IP packes
  }*/
}

void sr_handleARPPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  printf("handleARPPacket \n");
  /**/
  sr_arp_hdr_t *arphead;
  arphead = (sr_arp_hdr_t*) packet + sizeof(sr_ethernet_hdr_t);
  /*int match = 0;*/
   /*check if target IP matches one of your routers*/
  

  struct sr_if* ifIterator = sr->if_list;
  int n = 0;
  while(ifIterator->next){
    n++; /*keeps track of how many elements there are*/
    ifIterator = ifIterator->next;
    }
  uint32_t xorArray [n]; /*array the size of n IPs*/
  int leadingZeros  [n];

  ifIterator = sr->if_list;
  int i = 0;
  while(ifIterator->next){
    memset(&(xorArray[i]), (ifIterator->ip ^ arphead->ar_tip), 4);
    ifIterator  = ifIterator->next;
    i++;
  }
  int j;
  for(i = 0; i < n; i++)
  {
    for(j = 0; j < 32; j++)
    {
      leadingZeros[i] = 32; /*if there's no matches*/
      if(xorArray[i] & (1 << 31))
      {
        leadingZeros[i] = j;
        break;
      }
      else
      {
        xorArray[i] = xorArray[i] << 1;
      }
    }
  }
  int currentMin = 33;
  int minIndex = 0;
  for(i = 0; i < n; i++)
  {
    if(leadingZeros[i] < currentMin)
    {
      currentMin = leadingZeros[i];
      minIndex = i;
    }
  }
  ifIterator = sr->if_list;
  for(i = 0; i < minIndex; i++)
  {
    ifIterator = ifIterator->next;
  }

    
    if(arphead->ar_op == arp_op_request){
      /*handle ARP requests
        send a reply */

      sr_ethernet_hdr_t packet;
      /*packet.ether_dhost =*/ 

      /*send packet function in sr_vns_comm.c*/
      /*sr_send_packet()*/
      /*Eileen: I can't quite figure out what each argument of the send function is asking for
      may need to pass in the ethernet header to this functioin to extract the original sending
      host so we know who to send to here*/

    }
    else if(arphead->ar_op == arp_op_reply){
      /*handle ARP replies
        cache the request */

    }
}

bool isIMCP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
  return true; 
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*determine type of packet contained in ethernet frame*/
  sr_ethernet_hdr_t *header;
  header = (sr_ethernet_hdr_t*) packet;
  if(header->ether_type == ethertype_ip)
    sr_handleIPPacket(sr, packet, len, interface);
  else if(header->ether_type == ethertype_arp)
    sr_handleARPPacket(sr, packet, len, interface);

}/* end sr_ForwardPacket */

