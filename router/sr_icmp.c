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
  	sr_icmp_t11_hdr_t *icmp11Pkt;      /* time exceeded packet */
        sr_icmp_t3_hdr_t *icmp3Pkt;         
  	sr_icmp_hdr_t *icmp0pkt;
  	sr_ip_hdr_t *IPpkt;

	if (type == 0x0c){
          icmp11Pkt = malloc(sizeof(sr_icmp_t11_hdr_t));
          icmp11Pkt->type = type;
          icmp11Pkt->code = code;
          icmp11Pkt->sum = 0;
          icmp11Pkt->unused = 0;
          icmp11Pkt->data = data;
          icmp11Pkt->sum = cksum(icmp11Pkt, sizeof(sr_icmp_t11_hdr_t));
          IPpkt = malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
          memcpy(IPpkt + sizeof(sr_ip_hdr_t), icmp11Pkt, sizeof(sr_icmp_t11_hdr_t));
          IPpkt->ip_len = (sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ip_hdr_t));
        }
  	else if(type == 0x03){
          icmp3Pkt = malloc(sizeof(sr_icmp_t3_hdr_t));
	  icmp3Pkt->type = type;
	  icmp3Pkt->code = code;
	  icmp3Pkt->sum = 0;
	  icmp3Pkt->unused = 0;
	  icmp3Pkt->next_mtu = 0;
	  icmp3Pkt->data = data;
	  icmp3Pkt->sum = cksum(icmp3Pkt, sizeof(sr_icmp_t3_hdr_t));
          IPpkt = malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(IPpkt + sizeof(sr_ip_hdr_t), icmp3Pkt, sizeof(sr_icmp_t3_hdr_t));
          IPpkt->ip_len = (sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
	}
	else if(type == 0){
	  icmp0pkt->type = type;
	  icmp0pkt->code = code;
	  icmp0pkt->sum = 0;
	  icmp0pkt->sum = cksum(icmp0pkt, sizeof(sr_icmp_hdr_t));
          IPpkt = malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
          memcpy(IPpkt + sizeof(sr_ip_hdr_t), icmp0Pkt, sizeof(sr_icmp_hdr_t));
          IPpkt->ip_len = (sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t));
	}
        else
          printf("ICMP type not recognized\n");

	
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
