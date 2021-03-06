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



void sendIP(struct sr_instance* sr,
                                  sr_ip_hdr_t * IPpacket,
                                  unsigned int packet_len, /*should include length of all ICMP data*/
                                  char * iface)
{ /*CONFUSING: sr_packet is NOT an ethernet frame. An ethernet frame is an ethernet frame. This function takes in IP packets*/
    uint8_t *frame = malloc(sizeof(sr_ethernet_hdr_t) + packet_len);
    sr_ethernet_hdr_t *ether = (sr_ethernet_hdr_t*) frame;
    struct sr_if* interf = sr_get_interface(sr, iface);

    memcpy(ether->ether_shost, interf->addr, ETHER_ADDR_LEN);
    ether->ether_type = htons(ethertype_ip); /* Josh: changed to htons since we're sending to network right? */

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t*) (frame + sizeof(sr_ethernet_hdr_t));
    /*print_hdr_icmp(frame+sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));*/
    memcpy(iphdr, IPpacket, packet_len);

    /*printf("at this point wanted ip seems to be");
    print_addr_ip_int(ntohl(iphdr->ip_dst));
    printf("\n");*/
    /*check whether it's in the cache*/
  
    struct sr_arpentry * result = sr_arpcache_lookup(&sr->cache, iphdr->ip_dst);
    if(result != NULL)
    {

        /* there exists a mapping! send that mofo*/
        memcpy(ether->ether_dhost, result->mac, 6);
        /*printf("together size is %d\n", sizeof(sr_ethernet_hdr_t) + packet_len);
        //print_hdrs(frame, sizeof(sr_ethernet_hdr_t) + packet_len);*/
        sr_send_packet(sr, frame, sizeof(sr_ethernet_hdr_t) + packet_len, iface);
        free(frame);
    }

    else
    {
        /*no mapping  */
        sr_arpcache_queuereq(&sr->cache, iphdr->ip_dst, frame, sizeof(sr_ethernet_hdr_t) + IPpacket->ip_len, iface);
    }
}



sr_ip_hdr_t* sr_ICMPtoIP(uint8_t* packet, uint8_t type, uint8_t code, uint32_t rest, uint8_t* data, int len){
    	/* len is length of remaing ICMP message, data at the end of header */
    /*  sr_icmp_t11_hdr_t *icmp11Pkt; 
        sr_icmp_t3_hdr_t *icmp3Pkt;
        sr_icmp_hdr_t *icmp0pkt;
        printf("We malloc %d for icmp len\n", len);*/
	sr_icmp_hdr_t* icmp;
	sr_icmp_t3_hdr_t* icmp3;
        if (type == 0)
	{
          icmp = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));	
	  icmp->icmp_type = type;
	  icmp->icmp_code = code;
	  icmp->icmp_sum = 0;
          icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_hdr_t));
        }
	else
	{
	  icmp3 = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          icmp3->icmp_type = type;
          icmp3->icmp_code = code;
          icmp3->icmp_sum = 0;
          icmp3->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));
	}
        sr_ip_hdr_t *IPpkt = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
        IPpkt->ip_sum = 0;
        uint32_t temp = IPpkt->ip_src;
        IPpkt->ip_src = IPpkt->ip_dst;
        IPpkt->ip_dst = temp;
	if (type == 0)
        	IPpkt->ip_sum = cksum(IPpkt, IPpkt->ip_hl*4 + sizeof(sr_icmp_hdr_t));
	else
		IPpkt->ip_sum = cksum(IPpkt, IPpkt->ip_hl*4 + sizeof(sr_icmp_t3_hdr_t));
/*	print_hdr_ip((uint8_t*)IPpkt);
	if (type == 0)
        	print_hdr_icmp(icmp);
        else
		print_hdr_icmp(icmp3);*/
	return IPpkt;

}



void sr_handleIPPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  /*printf("handleIPPacket \n");*/
  
  sr_ip_hdr_t* ip_pack = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)); 
  
  /*verify checksum before proceeding further*/
  /*printf("length is %d\n", len-sizeof(sr_ethernet_hdr_t));
  printf("ip_pack->len = %d\n", ntohs(ip_pack->ip_len));*/
  uint8_t* buf = (uint8_t*)ip_pack;
  uint16_t original_chksum = ip_pack->ip_sum;
  ip_pack->ip_sum = 0;
  uint16_t computed_chksum = cksum(buf, ip_pack->ip_hl * 4);
  /*computed_chksum = cksum(ip_pack, ip_pack->ip_len);*/
  if (computed_chksum != original_chksum)
  {
    /*printf("computed checksum is %u\n", computed_chksum);
    printf("OG checksum is %u\n", original_chksum);*/
    printf("CHECKSUM FAILED \n");
    return;				/*drop the packet*/
  }
  /*printf("CHECKSUM WORKS AYYYY \n");*/
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
    /*printf("iAmDest\n");*/
    if (ip_pack->ip_p == ip_protocol_icmp)
    {
    	/* process pings and replies */

        /*printf("received a ping\n");*/
	sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_ip_hdr_t* echoReply = sr_ICMPtoIP(packet, 0, 0, icmp->icmp_idseq, (uint8_t*)(icmp + sizeof(sr_icmp_hdr_t)), 0);
        sendIP(sr, echoReply, ntohs(echoReply->ip_len), interface);
        /*free(echoReply);*/
    }
    else /* TCP or UDP protocol */
    {
        /*printf("TCP or UDP protocol\n");*/
        sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_ip_hdr_t* portUnreach = sr_ICMPtoIP(packet, 3, 3, icmp->icmp_idseq, (uint8_t*)(icmp + sizeof(sr_icmp_hdr_t)), len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t));
        sendIP(sr, portUnreach, ntohs(portUnreach->ip_len) , interface);
        /*free(portUnreach);*/
    }    
  }
  else
  {
    /*printf("Not Dest\n");*/
    /* fill in code to handle regular IP packets */
    ip_pack->ip_ttl--;
    if (ip_pack->ip_ttl == 0)
    {
      /* send time exceeded icmp message */
      /*printf("IP packet died... RIP IP\n");*/
      sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      sr_ip_hdr_t* timeExceed = sr_ICMPtoIP(packet, 11, 0, icmp->icmp_idseq, (uint8_t*)(icmp + sizeof(sr_icmp_hdr_t)), len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t));
      sendIP(sr, timeExceed, ntohs(timeExceed->ip_len) , interface);
      /*free(timeExceed);*/
    }
    /* recompute chksum after decrementing ttl */
    ip_pack->ip_sum = 0;

    ip_pack->ip_sum = cksum((const void*)ip_pack, ip_pack->ip_hl*4);

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
      /*printf("Routing entry not found\n");*/
      /*sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      sr_ip_hdr_t* netUnreach = sr_ICMPtoIP(packet, 3, 0, icmp->icmp_idseq, (uint8_t*)(icmp + sizeof(sr_icmp_hdr_t)), len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t));
      sendIP(sr, netUnreach, sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE, interface);
      free(netUnreach);*/
      sr_arpcache_queuereq(&sr->cache, ip_pack->ip_dst, (uint8_t*)ip_pack, ip_pack->ip_len,interface);
    }
    /* else get MAC of next hop and forward*/
    else
    {
      /*printf("Forwarding IP packet along of length %d\n", len-sizeof(sr_ethernet_hdr_t));
      printf("ip_pack->ip_len is %d\n", ntohs(ip_pack->ip_len));*/
      sendIP(sr, ip_pack, len - sizeof(sr_ethernet_hdr_t), interface);
    }
  }
}

void sr_handleARPPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  /*printf("handleARPPacket \n");*/
  
  /*struct sr_packet *srpack = (struct sr_packet*) packet;
  sr_ethernet_hdr_t* etherhead = (sr_ethernet_hdr_t*) srpack->buf;*/
  sr_ethernet_hdr_t* etherhead = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t *arphead;
  /*printf("sizeof(sr_ethernet_hdr_t) = %u\n", sizeof(sr_ethernet_hdr_t));*/
  arphead = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  /*int match = 0;*/
   /*check if target IP matches one of your routers*/
  

  struct sr_if* ifIterator = sr->if_list;
  struct sr_if* bestIfNA = NULL;
  uint32_t ipAddr = arphead->ar_tip;
  uint32_t datXorDoe = 0;
  uint32_t curMin = 0;
  while(ifIterator != NULL){
    datXorDoe = ipAddr ^ ifIterator->ip;
    if(datXorDoe < curMin || bestIfNA == NULL)
    {
        curMin = datXorDoe;
        bestIfNA = ifIterator;
    }
    ifIterator = ifIterator->next;
    }
    ifIterator = bestIfNA;
    /*printf("arphead->ar_op) = %u\n", arphead->ar_op);
    printf("ntohs(aprhead->ar_op) = %u\n", ntohs(arphead->ar_op));*/ 
    if(ntohs(arphead->ar_op) == arp_op_request){
      /*handle ARP requests
        send a reply */
        /*printf("oh! oh! It's an arp request!\n");*/
      uint8_t* repPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  
      sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t*) repPacket;
 
      memcpy(reply_ether->ether_dhost, etherhead->ether_shost, ETHER_ADDR_LEN);
  
      memcpy(reply_ether->ether_shost, ifIterator->addr, ETHER_ADDR_LEN);

      reply_ether->ether_type = ntohs(ethertype_arp);



      sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t*) (repPacket + sizeof(sr_ethernet_hdr_t));
      reply_arp->ar_hrd = ntohs(arp_hrd_ethernet);
      reply_arp->ar_pro = ntohs(ethertype_ip);
      reply_arp->ar_hln = 0x06;
      reply_arp->ar_pln = 0x04;
      reply_arp->ar_op = ntohs(arp_op_reply);
      memcpy(reply_arp->ar_sha, ifIterator->addr, ETHER_ADDR_LEN);
      reply_arp->ar_sip = ifIterator->ip;
      memcpy(reply_arp->ar_tha, arphead->ar_sha, ETHER_ADDR_LEN);
      reply_arp->ar_tip = arphead->ar_sip;

      sr_arpcache_insert(&(sr->cache),arphead->ar_sha, arphead->ar_sip);

      /*struct sr_packet *reply_frame = malloc(sizeof(struct sr_packet));
      reply_frame->buf = (uint8_t*)reply_ether;
      reply_frame->len = sizeof(*repPacket) + sizeof(struct sr_packet);
      reply_frame->iface = ifIterator->name;*/

      /*print_hdrs(repPacket, len);*/
      /*printf("iface is %s\n", ifIterator->name);

      printf("before sending \n");*/
      /*send packet function in sr_vns_comm.c*/
      sr_send_packet(sr, repPacket, len, ifIterator->name);
      /*printf("after sending \n");*/

    }
    else if(ntohs(arphead->ar_op) == arp_op_reply){
      /*handle ARP replies
        cache the request */
      /*printf("received an ARP reply!\n");*/
        struct sr_arpreq* insertedARP = sr_arpcache_insert(&(sr->cache),
                                                           arphead-> ar_sha,
                                                           arphead->ar_sip);
        if(NULL != insertedARP)
        {
            struct sr_packet* packetPointer = insertedARP->packets;
            while(packetPointer != NULL)
            {
                memcpy(packetPointer->buf, arphead->ar_sha, ETHER_ADDR_LEN);
               /* printf("LOOKIT MEEEE \n");*/
                sr_send_packet(sr, packetPointer->buf, packetPointer->len, interface);
                packetPointer = packetPointer->next;
            }
        }

    }
    /*printf("End of handling ARP packet\n");*/
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
/*
  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);*/
  /*determine type of packet contained in ethernet frame*/
  /*sr_ethernet_hdr_t *header;
  header = (sr_ethernet_hdr_t*) packet;*/
  uint16_t type = ethertype(packet);
  if(type == ethertype_ip)
  {
   /* printf("Got an IP packet!\n");*/
    sr_handleIPPacket(sr, packet, len, interface);
  }
  else if(type == ethertype_arp)
  {
    /*printf("Got an ARP packet!\n");*/
    sr_handleARPPacket(sr, packet, len, interface);
  }
  else
  {
    printf("Uhh...packet doesn't...have a thing\n");
  }
}/* end sr_ForwardPacket */

