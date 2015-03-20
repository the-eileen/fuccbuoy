#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_protocol.h"

/*void sendEchoReply(sr_ip_hdr_t* packet);*/
sr_ip_hdr_t* sr_ICMPtoIP(uint8_t type, uint8_t code, uint8_t data[], uint16_t id, uint32_t srcIP, uint32_t destIP);



#endif /* -- SR_ICMP_H -- */
