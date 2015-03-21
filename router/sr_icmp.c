/* contains functions for sending icmp messages */

#include "sr_icmp.h"

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
                                                                  
