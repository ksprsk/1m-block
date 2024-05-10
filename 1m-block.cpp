#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <set>
#include <cstring>
#include <fstream>
#include <libnetfilter_queue/libnetfilter_queue.h>

void usage() {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}
std::ifstream file;
std::set<std::string> lines;
const char* host="asdfas";


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb,uint32_t* id)
{
	*id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		*id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, *id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);
		
	if(ntohs(ph->hw_protocol)!=0x0800){fputc('\n', stdout);return true;}//not IPv4
	//IPv4
	printf("IPv4\n");
	uint32_t ipv4_IHL=data[0]&0xF;
	printf("header length=%u\n",ipv4_IHL<<2);
	printf("src IP:%u.%u.%u.%u\n",data[12],data[13],data[14],data[15]);
	printf("dst IP:%u.%u.%u.%u\n",data[16],data[17],data[18],data[19]);
	if(data[9]!=0x06){fputc('\n', stdout);return true;}//not TCP
	data+=ipv4_IHL<<2;
	//TCP
	printf("TCP\n");
	uint32_t tcp_data_offset=data[12]>>4;
	printf("header length=%u\n",tcp_data_offset<<2);
	uint16_t tcp_src_port=ntohs(*(uint16_t*)data);
	uint16_t tcp_dst_port=ntohs(*(uint16_t*)(data+2));
	printf("src port:%u\n",tcp_src_port);
	printf("dst port:%u\n",tcp_dst_port);
	data+=tcp_data_offset<<2;
	ret-=ipv4_IHL+tcp_data_offset<<2;
	//HTTP
	int len;
	for(len=0;len<=ret-4;len++)
	{	
		if(!strncmp((char*)data+len,"\r\n\r\n",4))break;
	}
	if(len>ret-4){fputc('\n', stdout);return true;}//not \r\n\r\n in remain data
	for(int i=0;i<len;i++)
	{
		printf("%c",data[i]);
	}
	
	for(int i=0;i<len-4;i++)
	{
		if(!strncmp((char*)data+i,"\r\nHost: ",8))
		{
			fputc('\n', stdout);
			fputc('\n', stdout);
			int host_len=0;
			while(strncmp((char*)data+i+8+host_len,"\r\n",2))host_len++;
			std::string str=std::string((char*)data+i+8,host_len);
			return lines.find(str)==lines.end();
		}
	}
	fputc('\n', stdout);
	fputc('\n', stdout);
	return true;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id; 
	bool check=print_pkt(nfa,&id);
	return nfq_set_verdict(qh, id, check?NF_ACCEPT:NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		usage();
		return false;
	}
	file.open(argv[1]);
	std::string line;
	while (std::getline(file, line)) {
		size_t comma_index = line.find(',');
		if (comma_index != std::string::npos) {
			line = line.substr(comma_index + 1);
		}
		lines.insert(line);
	}
	file.close();
	printf("file loaded\n");
	//this takes only 2sec. std::set<T>::find is O(log(n))
	/*
	std::string str("nave.com");
	for(int i=0;i<10000000;i++)
	{
		lines.find(str)!=lines.end();
	}
	printf("done?%d\n",lines.find(str)!=lines.end());
	*/
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
