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

#include <stdlib.h>

#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*#include "sr_icmp.h"*/

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



struct sr_packet * sr_createFrame(struct sr_instance* sr,
                                  uint8_t * IPpacket,
                                  unsigned int packet_len,
                                  char * iface)
{ /*CONFUSING: sr_packet is an ethernet frame.  This function takes in IP packets*/
    struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
    new_pkt-> buf = (uint8_t *)malloc(packet_len + 14); /*14 bytes; 6 for dest, 6 for src, 2 for ethtype*/

    memcpy((new_pkt->buf) + 14, IPpacket, packet_len);
    new_pkt->len = packet_len + 14;
    new_pkt->iface = (char*)malloc(sr_IFACE_NAMELEN);
    strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);

    struct sr_if* interfaceThing = sr_get_interface(sr, iface);

    memset((new_pkt->buf) + 8, 2048, 2); /*bytes are ezpz*/
    memcpy((new_pkt->buf) + 6, interfaceThing->addr, 6);
    /* next field not filled out */
    /* can just call queue req */
    return new_pkt;
}

void handleEthFrame(struct sr_instance* sr,
                    struct sr_arpcache *cache,
                    struct sr_packet * frame,
                    char * iface)
{
    /*check whether it's in the cache*/
    uint32_t destIP;
    memcpy(&destIP, (frame->buf)+30, 4);

    struct sr_arpentry * result = sr_arpcache_lookup(cache, destIP);
    if(result != NULL)
    {
        /* there exists a mapping! send that mofo*/
        memcpy(frame->buf, result->mac, 6);
        sr_send_packet(sr, frame->buf, frame->len, iface);
        /* free(frame) */
    }
    else
    {
        /*no mapping RIPPERINO */
        sr_arpcache_queuereq(&sr->cache, destIP, frame->buf, frame->len, iface);
    }
}


sr_ip_hdr_t* sr_ICMPtoIP(uint8_t type, uint8_t code, uint8_t data[], uint16_t id, uint32_t srcIP, uint32_t destIP){
        sr_icmp_t11_hdr_t *icmp11Pkt;      /* time exceeded packet */
        sr_icmp_t3_hdr_t *icmp3Pkt;
        sr_icmp_hdr_t *icmp0pkt;
        sr_ip_hdr_t *IPpkt;

        if (type == 0x0c){
          icmp11Pkt = malloc(sizeof(sr_icmp_t11_hdr_t));
          icmp11Pkt->icmp_type = type;
          icmp11Pkt->icmp_code = code;
          icmp11Pkt->icmp_sum = 0;
          icmp11Pkt->unused = 0;
          memcpy(icmp11Pkt->data, data, ICMP_DATA_SIZE);
          icmp11Pkt->icmp_sum = cksum(icmp11Pkt, sizeof(sr_icmp_t11_hdr_t));
          IPpkt = malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
          memcpy(IPpkt + sizeof(sr_ip_hdr_t), icmp11Pkt, sizeof(sr_icmp_t11_hdr_t));
          IPpkt->ip_len = (sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ip_hdr_t));
        }
        else if(type == 0x03){
          icmp3Pkt = malloc(sizeof(sr_icmp_t3_hdr_t));
          icmp3Pkt->icmp_type = type;
          icmp3Pkt->icmp_code = code;
          icmp3Pkt->icmp_sum = 0;
          icmp3Pkt->unused = 0;
          icmp3Pkt->next_mtu = 0;
          memcpy(icmp3Pkt->data, data, ICMP_DATA_SIZE);
          icmp3Pkt->icmp_sum = cksum(icmp3Pkt, sizeof(sr_icmp_t3_hdr_t));
          IPpkt = malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(IPpkt + sizeof(sr_ip_hdr_t), icmp3Pkt, sizeof(sr_icmp_t3_hdr_t));
          IPpkt->ip_len = (sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
        }
        else if(type == 0){
          icmp0pkt = malloc(sizeof(sr_icmp_hdr_t));
          icmp0pkt->icmp_type = type;
          icmp0pkt->icmp_code = code;
          icmp0pkt->icmp_sum = 0;
          icmp0pkt->icmp_sum = cksum(icmp0pkt, sizeof(sr_icmp_hdr_t));
          IPpkt = malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
          memcpy(IPpkt + sizeof(sr_ip_hdr_t), icmp0pkt, sizeof(sr_icmp_hdr_t));
          IPpkt->ip_len = (sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t));
        }
        else
          printf("ICMP type not recognized\n");


        IPpkt->ip_tos = 0;
        IPpkt->ip_id = id;
        IPpkt->ip_off = 0;
        IPpkt->ip_ttl = 0x64;
        IPpkt->ip_p = ip_protocol_icmp;
        IPpkt->ip_sum = 0;
        IPpkt->ip_src = srcIP;
        IPpkt->ip_dst = destIP;
        IPpkt->ip_sum = cksum(IPpkt, IPpkt->ip_len);

        return IPpkt;
}



void sr_handleIPPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  printf("handleIPPacket \n");
  
  sr_ip_hdr_t* ip_pack = (sr_ip_hdr_t*) packet; 
  
  /*verify checksum before proceeding further*/
  uint16_t original_chksum = ip_pack->ip_sum;
  ip_pack->ip_sum = 0;
  uint16_t computed_chksum = 0;
  computed_chksum = cksum((const void*)ip_pack, ip_pack->ip_len);
  if (computed_chksum != original_chksum)
  {
    printf("CHECKSUM FAILED \n");
    return;				/*drop the packet*/
  }
  printf("CHECKSUM WORKS AYYYY \n");
  bool amIDest = false;
  struct sr_if* inter = sr->if_list;
  while (inter != NULL) /*check each to check whether we're the dest*/
  {
    if (inter->ip == ip_pack->ip_dst)
    {
      amIDest = true;
      break;
    }
    inter = inter->next;
  }
  
  if(amIDest) 
  {
    /* fill in code to handle ICMP stuff */
    printf("iAmDest\n");
    if (ip_pack->ip_p == ip_protocol_icmp)
    {
    	/* process pings and replies */
        printf("received a ping");
        uint8_t data[ICMP_DATA_SIZE];
        memcpy(data, ip_pack, ICMP_DATA_SIZE);
        sr_ip_hdr_t* echoReply = sr_ICMPtoIP(0, 0, data, ip_pack->ip_id, ip_pack->ip_dst, ip_pack->ip_src);
        sr_send_packet(sr, (uint8_t*)echoReply, echoReply->ip_len, interface);
        free(echoReply);
    }
    else /* TCP or UDP protocol */
    {
        uint8_t data[ICMP_DATA_SIZE];
        memcpy(data, ip_pack, ICMP_DATA_SIZE);
        sr_ip_hdr_t* portUnreach = sr_ICMPtoIP(3, 3, data, ip_pack->ip_id, ip_pack->ip_dst, ip_pack->ip_src);
        sr_send_packet(sr, (uint8_t*)portUnreach, portUnreach->ip_len, interface);
        free(portUnreach);
    }    
  }
  else
  {
    /* fill in code to handle regular IP packets */
    ip_pack->ip_ttl--;
    if (ip_pack->ip_ttl == 0)
    {
      /* send time exceeded icmp message */
      uint8_t data[ICMP_DATA_SIZE];
      memcpy(data, ip_pack, ICMP_DATA_SIZE);
      sr_ip_hdr_t* timeExceed = sr_ICMPtoIP(11, 0, data, ip_pack->ip_id, ip_pack->ip_dst, ip_pack->ip_src);
      sr_send_packet(sr, (uint8_t*)timeExceed, timeExceed->ip_len, interface);
      free(timeExceed);
    }
    /* recompute chksum after decrementing ttl */
    ip_pack->ip_sum = 0;
    ip_pack->ip_sum = cksum(ip_pack, ip_pack->ip_len);
    struct sr_rt* entry = sr->routing_table;
    while (entry != NULL)
    {
      if (entry->dest.s_addr  == ip_pack->ip_dst)
        break;
      entry = entry->next;
    }
    /* if routing entry not found, send ICMP network unreachable message */
    if (entry == NULL)
    {
      uint8_t data[ICMP_DATA_SIZE];
      memcpy(data, ip_pack, ICMP_DATA_SIZE);
      sr_ip_hdr_t* netUnreach = sr_ICMPtoIP(3, 0, data, ip_pack->ip_id, ip_pack->ip_dst, ip_pack->ip_src);
      sr_send_packet(sr, (uint8_t*) netUnreach, netUnreach->ip_len, interface);
      free(netUnreach);
    }
    /* else get MAC of next hop */
    else
    {
      struct sr_packet* ethFrame = sr_createFrame(sr, (uint8_t*)ip_pack, ip_pack->ip_len, interface);
      handleEthFrame(sr, &(sr->cache), ethFrame, interface);
    }
  }
}

void sr_handleARPPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  printf("handleARPPacket \n");
  /**/
  sr_ethernet_hdr_t* etherhead = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t *arphead;
  printf("sizeof(sr_ethernet_hdr_t) = %u\n", sizeof(sr_ethernet_hdr_t));
  arphead = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
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
    printf("arphead->ar_op) = %u\n", arphead->ar_op);
    printf("ntohs(aprhead->ar_op) = %u\n", ntohs(arphead->ar_op)); 
    if(ntohs(arphead->ar_op) == arp_op_request){
      /*handle ARP requests
        send a reply */
        printf("oh! oh! It's an arp request! okok let me try! \n");
      uint8_t* repPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t*) repPacket;
      memcpy(reply_ether->ether_dhost, etherhead->ether_shost, ETHER_ADDR_LEN);
      memcpy(reply_ether->ether_shost, etherhead->ether_dhost, ETHER_ADDR_LEN);
      reply_ether->ether_type = ethertype_arp;

      sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t*) reply_ether + sizeof(sr_ethernet_hdr_t);
      reply_arp->ar_hrd = arp_hrd_ethernet;
      reply_arp->ar_pro = ethertype_arp;
      reply_arp->ar_hln = 0x06;
      reply_arp->ar_pln = 0x04;
      reply_arp->ar_op = arp_op_reply;
      memcpy(reply_arp->ar_sha, ifIterator->addr, ETHER_ADDR_LEN);
      reply_arp->ar_sip = ifIterator->ip;
      memcpy(reply_arp->ar_tha, arphead->ar_sha, ETHER_ADDR_LEN);
      reply_arp->ar_tip = arphead->ar_sip;

      struct sr_packet *reply_frame = malloc(sizeof(struct sr_packet));
      reply_frame->buf = (uint8_t*)repPacket;
      reply_frame->len = sizeof(*repPacket) + sizeof(struct sr_packet);
      reply_frame->iface = ifIterator->name;

      /*send packet function in sr_vns_comm.c*/
      sr_send_packet(sr, (uint8_t*)reply_frame, reply_frame->len, reply_frame->iface);

    }
    else if(ntohs(arphead->ar_op) == arp_op_reply){
      /*handle ARP replies
        cache the request */
      printf("received an ARP reply!\n");
        struct sr_arpreq* insertedARP = sr_arpcache_insert(&(sr->cache),
                                                           arphead-> ar_sha,
                                                           arphead->ar_sip);
        if(NULL != insertedARP)
        {
            struct sr_packet* packetPointer = insertedARP->packets;
            while(packetPointer != NULL)
            {
                memcpy(packetPointer->buf, arphead->ar_sha, ETHER_ADDR_LEN);
                sr_send_packet(sr, packetPointer->buf, packetPointer->len, interface);
                packetPointer = packetPointer->next;
            }
        }

    }
    printf("End of handling ARP packet\n");
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
  print_hdrs(packet, len);
  /*determine type of packet contained in ethernet frame*/
  sr_ethernet_hdr_t *header;
  header = (sr_ethernet_hdr_t*) packet;
  uint16_t type = ethertype(packet);
  if(type == ethertype_ip)
  {
    printf("Got an IP packet!\n");
    sr_handleIPPacket(sr, packet, len, interface);
  }
  else if(type == ethertype_arp)
  {
    printf("Got an ARP packet!\n");
    sr_handleARPPacket(sr, packet, len, interface);
  }
  else
  {
    printf("Uhh...packet doesn't...have a thing\n");
  }
}/* end sr_ForwardPacket */

