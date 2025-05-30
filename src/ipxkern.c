/*
    IPX support library - kernel dependent functions

    Copyright (C) 1994, 1995  Ales Dryak <e-mail: A.Dryak@sh.cvut.cz>
    Copyright (C) 1996, Volker Lendecke <lendecke@namu01.gwdg.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 0)
#include <netipx/ipx.h>
#include <net/route.h>
#else
#include "linux/ipx.h"
#include <linux/route.h>
#endif
#include "ipxkern.h"

#define MAX_IFC (256)

static int 
asc2frame(char *frame)
{
	if (strcasecmp("etherii", frame) == 0)
		return IPX_FRAME_ETHERII;
	else if (strcasecmp("802.2", frame) == 0)
		return IPX_FRAME_8022;
	else if (strcasecmp("802.3", frame) == 0)
		return IPX_FRAME_8023;
	else if (strcasecmp("snap", frame) == 0)
		return IPX_FRAME_SNAP;
	else
		return 0;
}

int
ipx_kern_scan_rtable(IPXrtScanFunc f, void *data)
{
	FILE *ipx_route;
	char buf[512];

	ipx_route = fopen("/proc/net/ipx/route", "r");

	if (ipx_route == NULL)
	{
		sprintf(ipx_err_string, "open ipx_route: %s",
			strerror(errno));
		return -1;
	}

	/* ignore header line */
	fgets(buf, sizeof(buf), ipx_route);

	while (fgets(buf, sizeof(buf), ipx_route) != NULL)
	{
		IPXNet network;
		IPXNet router_net;
		IPXNode router_node;
		int type = 0;

		if (strncmp(&(buf[11]), "Directly", 8) == 0)
		{
			if (ipx_sscanf_net(buf, &network) != 0)
			{
				fclose(ipx_route);
				return -1;
			}
			router_net = 0;
			memset(router_node, 0, sizeof(router_node));
		}
		else
		{
			type |= IPX_KRT_ROUTE;

			if (   (ipx_sscanf_net(buf, &network) != 0)
			    || (ipx_sscanf_net(&(buf[11]), &router_net) != 0)
			    || (ipx_sscanf_node(&(buf[24]), router_node) != 0))
			{
				fclose(ipx_route);
				return -1;
			}
		}

		if (f(network, router_net, router_node, type, data) != 0)
		{
			fclose(ipx_route);
			return 0;
		}
	}
	fclose(ipx_route);
	return 1;
}
		
int
ipx_kern_scan_ifaces(IPXifcScanFunc f, void *data)
{
	FILE *ipx_ifc;
	char buf[512];

	ipx_ifc = fopen("/proc/net/ipx/interface", "r");

	if (ipx_ifc == NULL)
	{
		sprintf(ipx_err_string, "open ipx_interface: %s",
			strerror(errno));
		return -1;
	}

	/* ignore header line */
	fgets(buf, sizeof(buf), ipx_ifc);

	while (fgets(buf, sizeof(buf), ipx_ifc) != NULL)
	{
		IPXNet network;
		IPXNode node;
		int type = 0;
		char device[128];
		int i;
		int result;

		type = asc2frame(&(buf[46]));
		
		if (strncmp(&(buf[35]), "Internal", 8) == 0)
		{
			type |= IPX_KRT_INTERNAL;
		}

		if (   (ipx_sscanf_net(buf, &network) != 0)
		    || (ipx_sscanf_node(&(buf[11]), node) != 0))
		{
			fclose(ipx_ifc);
			return -1;
		}

		memset(device, 0, sizeof(device));

		for (i = 0; i < sizeof(device)-1; i++)
		{
			if (buf[i+35] == ' ')
			{
				break;
			}
			device[i] = buf[i+35];
		}

		if ((result = f(network, node, device, type, data)) != 0)
		{
			fclose(ipx_ifc);
			return result;
		}
	}
	fclose(ipx_ifc);
	return 0;
}

int
ipx_kern_route_add(int sock, IPXNet net, IPXNet rt_net, IPXNode rt_node)
{
	struct rtentry rt;
	struct sockaddr_ipx* sr;
	struct sockaddr_ipx* st;
	
	sr=(struct sockaddr_ipx*)&rt.rt_gateway;
	st=(struct sockaddr_ipx*)&rt.rt_dst;
	
	sr->sipx_family=st->sipx_family=AF_IPX;
	st->sipx_network=htonl(net);
	sr->sipx_network=htonl(rt_net);
	ipx_assign_node(sr->sipx_node,rt_node);
	rt.rt_flags=RTF_GATEWAY;

	if(ioctl(sock,SIOCADDRT,(void *)&rt)!=0)
	{
		sprintf(ipx_err_string,"ioctl SIOCADDRT: %s",strerror(errno));
		return -1;
	}
	return 0;
}

int
ipx_kern_route_delete(int sock, IPXNet net)
{
	struct rtentry rt;
	struct sockaddr_ipx* sr;
	struct sockaddr_ipx* st;
	
	sr=(struct sockaddr_ipx*)&rt.rt_gateway;
	st=(struct sockaddr_ipx*)&rt.rt_dst;
	
	sr->sipx_family=st->sipx_family=AF_IPX;
	st->sipx_network=htonl(net);
	rt.rt_flags=RTF_GATEWAY;

	if(ioctl(sock,SIOCDELRT,(void *)&rt)!=0)
	{
		sprintf(ipx_err_string,"ioctl SIOCDELRT: %s",strerror(errno));
		return -1;
	}
	return 0;
}

int
ipx_kern_enable_broadcast(int sock)
{
	int opt=1;
	/* Permit broadcast output */
	if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST, &opt,sizeof(opt))==-1)
	{
		sprintf(ipx_err_string,"setsockopt SO_BROADCAST: %s",
			strerror(errno));
		return -1;
	}
	return 0;
}
