#include "packet_seq.h"
#include <alloca.h>
#include <arpa/inet.h>
#include <cmath>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define HS_clientHello 1
#define HS_serverHello 2
#define HANDSHAKE 22
#define APPLICATOIN 23
#define TLS_13 0x0304
time_t timetmp;
pcap_if_t *alldevs;
char *interface = "enp10s0";
const u_char *packet;
pcap_t *handle; // session handler
char err[PCAP_BUF_SIZE];
struct bpf_program fp;
bpf_u_int32 mask; /* subnet mask */
bpf_u_int32 net;
const char filter_exp[] = "port 443";
u_short totalBytes;
u_char *connection[35];
u_char Hello_payload[1024];
u_char Server_payload[1024];
u_char *header_payload;
u_char *body_payload;
size_t payload_size;
double e4_entropy_h;
double e4_entropy_c;
clock_t start_flow;
clock_t end_flow;
double flow_duration;
void printInterfaces() {
  int status;

  if ((status = pcap_findalldevs(&alldevs, err)) != 0) {
    printf("error finding device to capture %s", err);
  }
  for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
    printf("%s\n", d->name);
  }
  pcap_freealldevs(alldevs);
}

void get_tcp_flags_str(uint8_t flags, char *buffer, size_t max_len) {
  if (flags == 0) {
    snprintf(buffer, max_len, "NONE");
    return;
  }
  snprintf(buffer, max_len, "%s%s%s%s%s%s%s%s", (flags & TH_FIN) ? "FIN " : "",
           (flags & TH_SYN) ? "SYN " : "", (flags & TH_RST) ? "RST " : "",
           (flags & TH_PUSH) ? "PUSH " : "", (flags & TH_ACK) ? "ACK " : "",
           (flags & TH_URG) ? "URG " : "", (flags & TH_ECE) ? "ECE " : "",
           (flags & TH_CWR) ? "CWR " : "");
}
double entropy(u_char *data, int size) {
  u_short c = 0;
  double H = 0;
  int buffer[256] = {0};
  /* calculating frequency of each character byte */
  for (int i = 0; i > size; i++) {
    c = data[i];
    buffer[c]++;
  }
  /*calculating entropy */
  for (int i = 0; i < size; i++) {
    double avg = (double)buffer[i] / size;
    H = H - avg * log2((double)buffer[i] / size);
  }
  return H;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_tls *payload;
  const struct Handshake *handshake;
  const struct Server_Hello *server_hello;
  const struct Client_Hello *client_hello;
  const struct Application *app_payload;

  u_int size_payload = 0;
  u_int size_tlsHeader = 5;
  char flag_str[64] = "N/A";
  const char *protocol_str = "UNKNOWN";
  ethernet = (const struct sniff_ethernet *)(packet);
  ip = (const struct sniff_ip *)(packet + SIZE_ETHERNET);

  u_int size_ip = IP_HL(ip) * 4;

  if (size_ip < 20) {
    return;
  }

  protocol_str = "TCP";
  tcp = (const struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
  u_int size_tcp = TH_OFF(tcp) * 4;

  if (size_tcp < 20) {
    fprintf(stderr, "Invalid TCP header length: %u\n", size_tcp);
    return;
  }

  payload =
      (const struct sniff_tls *)packet + SIZE_ETHERNET + size_ip + size_tcp;
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
  get_tcp_flags_str(tcp->th_flags, flag_str, sizeof(flag_str));

  if (payload->tlsh_contt == HANDSHAKE) {
    totalBytes += payload->tlsh_len;
    handshake = ((const struct Handshake *)packet + SIZE_ETHERNET + size_ip +
                 size_tcp + size_tlsHeader);
    server_hello = (const struct Server_Hello *)handshake;
    client_hello = (const struct Client_Hello *)handshake;

    if (server_hello->tlsh_ExtSup_tls_version == TLS_13) {

      if (handshake->tlsh_hdsht == HS_serverHello) {
        end_flow = clock();
        flow_duration = (double)(end_flow - start_flow) / CLOCKS_PER_SEC;
        totalBytes += payload->tlsh_len;
        memcpy(Server_payload, (void *)server_hello, server_hello->tlsh_hdsht);
        header_payload = malloc(sizeof(Hello_payload) + sizeof(Server_payload));
        memcpy(Hello_payload, header_payload, sizeof(Hello_payload));
        memcpy(Hello_payload + sizeof(Hello_payload), Server_payload,
               sizeof(Server_payload));
        e4_entropy_h = entropy(header_payload, sizeof(header_payload));
        connection[1] = (u_char *)server_hello->tlsh_SessionId;
        connection[5] = (u_char *)server_hello->tlsh_ExtKey_Group;
        connection[7] = (u_char *)server_hello->tlsh_ExtKey_len;
        connection[9] = (u_char *)server_hello->tlsh_rclen;

      } else if (handshake->tlsh_hdsht == HS_clientHello) {
        start_flow = clock();
        totalBytes += payload->tlsh_len;
        memcpy(Server_payload, (void *)server_hello, server_hello->tlsh_hdsht);
        connection[4] = (u_char *)ctime(&timetmp);
        u_char *keyptr = (u_char *)client_hello + 109;
        const struct Client_Hello *tmp = (const struct Client_Hello *)keyptr;

        while (tmp->Ext.tlsh_type != 51) {
          keyptr += tmp->Ext.tlsh_len;
        }

        connection[6] = (u_char *)tmp->Keyshare.tlsh_Client_Key_Share;
        connection[8] = (u_char *)client_hello->tlsh_rclen;
      }
    }
    if (server_hello->tlsh_ExtSup_tls_version < TLS_13) {
      const struct Server_key_exchange *Server_key_exchange;
      Server_key_exchange = (const struct Server_key_exchange *)handshake;
      connection[11] = (u_char *)Server_key_exchange->tlsh2_sig_alg;
      connection[12] = (u_char *)"True";
    }
  } else if (handshake->tlsh_hdsht == APPLICATOIN) {
    app_payload = (const struct Application *)payload;
    if (sizeof(app_payload) < sizeof(body_payload)) {
      payload_size += sizeof(body_payload);
      memcpy(body_payload + payload_size, app_payload, sizeof(app_payload));
    }
  }
  FILE *fp = (FILE *)args;
  if (fp == NULL) {
    fprintf(stderr, "error: file pointer is NULL\n");
    return;
  }
  if (tcp->th_flags == TH_FIN) {
    e4_entropy_c = entropy(body_payload, sizeof(body_payload));
    exit(0);
  }
  char *scenario_id = "raf_test";
  setvbuf(fp, NULL, _IOLBF, 0);
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  strncpy(src_ip, inet_ntoa(ip->ip_src), INET_ADDRSTRLEN);
  strncpy(dst_ip, inet_ntoa(ip->ip_dst), INET_ADDRSTRLEN);

  // logic :
  if (payload->tlsh_SessionIdlen)
    time(&timetmp);
  fprintf(fp, "%s,%s,%s, %s,%s,%d,%d\n", scenario_id, payload->tlsh_SessionId,
          src_ip, dst_ip, dst_ip, ctime(&timetmp), payload->tlsh_ExtKey_Group,
          payload->tlsh_hdlen, payload->tlsh_len, size_payload, );
  fflush(fp);
}
void establishConnetion() {

  if (pcap_lookupnet(interface, &net, &mask, err) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, err);
    net = 0;
    mask = 0;
  }
  if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err)) == NULL) {
    printf("couldn't open %s device for capture: %s", interface, err);
    exit(1);
  }
  if ((pcap_compile(handle, &fp, filter_exp, 0, net)) != 0) {
    printf("filed compiling filters");
    exit(1);
  }
  if (pcap_setfilter(handle, &fp) != 0) {
    printf("error applying filters");
    exit(1);
  }
  // Pass pipe_fp as args so got_packet can write to it
  pcap_loop(handle, -1, got_packet, (u_char *)stdout);

  pcap_freecode(&fp);
  pcap_close(handle);
}

int main() {
  body_payload = malloc((size_t)1024);
  establishConnetion();
}
