#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include <stdio.h>
#include "arp.h"

#define INVALID_VALUE -1
#define SUCCESS_VALUE 0

using namespace std;

uint16_t Arp::op_reply = ARPOP_REPLY;

Arp::Arp()
{
	this->handle = libnet_init(LIBNET_LINK, NULL, this->errorMsg);
	if (this->handle == NULL)
	{
		this->errorLog();
		valid = 0;
		return;
	}
	initialize();
	valid = 1;
}

Arp::Arp(const char *device)
{
	this->handle = libnet_init(LIBNET_LINK, device, this->errorMsg);
	if (this->handle == NULL)
	{
		valid = 0;
		this->errorLog();
		return;
	}
	initialize();
	valid = 1;
}

Arp::~Arp()
{
	if (valid && this->handle) 
	{
		libnet_destroy(this->handle);
	}
}

int Arp::initialize()
{
	return 0;
}

const char *Arp::getDevice()
{
	return libnet_getdevice(this->handle);
}

void Arp::errorLog()
{
	if (this->handle)
	{
		cerr << libnet_geterror(this->handle) << endl;
	}
	cerr << this->errorMsg << endl;
	return;
}

void Arp::getInfo()
{
	if (!valid)
	{
		return;
	}
	const char *device;
	device = libnet_getdevice(this->handle);
	if (device)
	{
		cout.flags(ios::left);
		cout << setw(20) << "Device name :" << libnet_getdevice(this->handle) << endl;
	}
	in_addr inaddr;
	inaddr.s_addr = libnet_get_ipaddr4(this->handle);
	if (inaddr.s_addr != INVALID_VALUE)
	{
		cout.flags(ios::left);
		cout << setw(20) << "IP Address :" << inet_ntoa(inaddr) << endl;
	}
	libnet_ether_addr *phAddr;
	phAddr = libnet_get_hwaddr(this->handle);
	if (phAddr)
	{
		cout.flags(ios::left | ios::hex);
		cout << setw(20) << "Physicial Address :" << setfill('0') << setw(2)
			<< (int)phAddr->ether_addr_octet[0] 
			<< "-" << (int)phAddr->ether_addr_octet[1]
			<< "-" << (int)phAddr->ether_addr_octet[2]
			<< "-" << (int)phAddr->ether_addr_octet[3]
			<< "-" << (int)phAddr->ether_addr_octet[4]
			<< "-" << (int)phAddr->ether_addr_octet[5]
			<< endl;
	}
	return;
}

u_int32_t Arp::name2addr(char* addr)
{
	return libnet_name2addr4(this->handle, addr, LIBNET_RESOLVE);
}

int Arp::phAddrFromStr(char *in, libnet_ether_addr *out)
{
	int icount;
	icount = sscanf(in, "%X:%X:%X:%X:%X:%X", 
		(int*)&out->ether_addr_octet[0],
		(int*)&out->ether_addr_octet[1],
		(int*)&out->ether_addr_octet[2],
		(int*)&out->ether_addr_octet[3],
		(int*)&out->ether_addr_octet[4],
		(int*)&out->ether_addr_octet[5]);
	if (icount != sizeof(*out))
	{
		return INVALID_VALUE;
	}
	return SUCCESS_VALUE;
}

libnet_ptag_t Arp::build_packet(const libnet_ether_addr *srcPhAddr, 
	const u_int32_t srcProAddr, 
	const libnet_ether_addr *dstPhAddr, 
	const u_int32_t dstProAddr, 
	uint16_t op)
{
	libnet_ptag_t ret = libnet_build_arp(ARPHRD_ETHER, 
		ETHERTYPE_IP, 
		6, // physical address size
		4, // protocol address size 
		op, 
		(const uint8_t *)srcPhAddr,
		(const uint8_t *)&srcProAddr,
		(const uint8_t *)dstPhAddr,
		(const uint8_t *)&dstProAddr,
		NULL, 
		0, 
		this->handle, 
		0);
	if (ret == INVALID_VALUE)
	{
		return ret;
	}

	return libnet_build_ethernet(
		(const uint8_t *)dstPhAddr,
		(const uint8_t *)srcPhAddr,
		ETHERTYPE_ARP,
		NULL, 
		0, 
		this->handle,
		0);
}

int Arp::arp(char *strSrcPhAddr, 
	char *strSrcProAddr, 
	char *strDstPhAddr, 
	char *strDstProAddr, 
	const int op)
{
	libnet_ether_addr srcPhAddr, dstPhAddr;
	u_int32_t srcProAddr, dstProAddr;
	srcProAddr = this->name2addr(strSrcProAddr);
	dstProAddr = this->name2addr(strDstProAddr);
	this->phAddrFromStr(strSrcPhAddr, &srcPhAddr);
	this->phAddrFromStr(strDstPhAddr, &dstPhAddr);

	libnet_ptag_t packet = this->build_packet(&srcPhAddr, srcProAddr, &dstPhAddr, dstProAddr, op);
	if (packet == INVALID_VALUE)
	{
		return INVALID_VALUE;
	}
	int iret = libnet_write(this->handle);
	if (iret == INVALID_VALUE)
	{
		this->errorLog();
	}
	return iret;
}
