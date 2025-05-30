/*

    IPX support library

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
#ifndef __IPXKERN_H__

#define __IPXKERN_H__

#include "ipxutil.h"

#define IPX_KRT_INTERNAL (1)
#define IPX_KRT_ROUTE    (2)

typedef int (*IPXifcScanFunc)(IPXNet,IPXNode,char *,int,void*);
typedef int (*IPXrtScanFunc)(IPXNet,IPXNet,IPXNode,int,void*);

int ipx_kern_enable_broadcast(int sock);
int ipx_kern_route_add(int sock,IPXNet net,IPXNet rt_net,IPXNode rt_node);
int ipx_kern_route_delete(int sock,IPXNet net);            
int ipx_kern_scan_ifaces(IPXifcScanFunc f,void* data);
int ipx_kern_scan_rtable(IPXrtScanFunc f,void* data);

#endif /* __IPXKERN_H__ */
