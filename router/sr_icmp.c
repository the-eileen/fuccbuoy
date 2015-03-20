/* contains functions for sending icmp messages */

#include "sr_icmp.h"


/*void sendEchoReply(sr_ip_hdr_t* packet)
{
  sr_icmp_hdr_t reply;
  reply.icmp_type = 0;
  reply.icmp_code = 0;
  reply.icmp_sum = 0;
  reply.icmp_sum = cksum(reply, 4);
  
}
*/

sr_ip_hdr_t* sr_ICMPtoIP(uint8_t type, uint8_t code, uint8_t data[], uint16_t id, uint32_t srcIP, uint32_t destIP){
  	sr_icmp_t3_hdr_t *icmpPkt = malloc(sizeof(sr_icmp_t3_hdr_t));
  	sr_icmp_hdr_t *pkt = malloc(sizeof(sr_icmp_hdr_t));
  	sr_ip_hdr_t *IPpkt = malloc(sizeof(sr_ip_hdr_t));

  	if(type == 0x03){
	  IPpkt->ip_len = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t);
	  icmpPkt->type = type;
	  icmpPkt->code = code;
	  icmpPkt->sum = 0;
	  icmpPkt->unused = 0;
	  icmpPkt->next_mtu = 0;
	  icmpPkt->data = data;
	  icmpPkt->sum = cksum(icmpPkt, sizeof(sr_icmp_t3_hdr_t));
	}
	else if(type == 0){
	  IPpkt->ip_len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t);
	  pkt->type = type;
	  pkt->code = code;
	  pkt->sum = 0;
	  pkt->sum = cksum(pkt, sizeof(sr_icmp_hdr_t));
	}

	
	IPpkt->ip_tos = 0;
	IPpkt->ip_id = id;
	IPpkt->ip_off = 0;
	IPpkt->ip_ttl = 0x128;
	IPpkt->ip_p = ip_protocol_icmp;
	IPpkt->ip_sum = 0;
	IPpkt->ip_src = srcIP;
	IPpkt->ip_dst = destIP;
	pkt->sum = cksum(IPpkt, IPpkt->ip_len);

	return IPpkt;
}