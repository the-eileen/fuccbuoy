/* contains functions for sending icmp messages */

#include "sr_icmp.h"


void sendEchoReply(sr_ip_hdr_t* packet)
{
  sr_icmp_hdr_t reply;
  reply.icmp_type = 0;
  reply.icmp_code = 0;
  reply.icmp_sum = 0;
  reply.icmp_sum = cksum(reply, 4);
  
}
