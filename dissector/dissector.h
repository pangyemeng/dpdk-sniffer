#ifndef DISSECTOR_H_
#define DISSECTOR_H_

int dissect_packet(struct rte_mbuf *mbuf, packet_t *pkt);
void print_packet_info(packet_t *pkt);

#endif /* DISSECTOR_H_ */
