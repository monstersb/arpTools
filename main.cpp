#include <stdio.h>
#include "arp.h"

int main(int argc, char *argv[])
{
	Arp arp(argv[1]);
	arp.getInfo();
	return arp.arp(argv[2], argv[3], argv[4], argv[5], arp.op_reply);
}
