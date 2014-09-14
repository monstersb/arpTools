#include <libnet.h>

class Arp
{
public:
	Arp();
	Arp(const char *dev);
	
	~Arp();

	const char *getDevice();
	void errorLog();
	void getInfo();
	int arp(char *strSrcPhAddr, char *strSrcProAddr, char *strDstPhAddr, char *strDstProAddr, const int op);

private:
	int initialize();
	u_int32_t name2addr(char* addr);
	int phAddrFromStr(char *in, libnet_ether_addr *out);
	libnet_ptag_t build_packet(const libnet_ether_addr *srcPhAddr, const u_int32_t srcProAddr, const libnet_ether_addr *dstPhAddr, const u_int32_t dstProAddr, uint16_t op);

public:
	static uint16_t op_reply;

private:
	libnet_t *handle;
	int valid;
	char errorMsg[1024];
};
