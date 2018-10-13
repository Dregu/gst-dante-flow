/*
 * Project: mcscanner - Multicast Network Scanner
 * File name: mcSniff.cpp
 * Description:  This program (mcscanner) scans a network for multicast sources and traffic,
 *   which are explicitly avoided in typical network scanners such as nmap.
 *   The program sends PIM Hello and IGMP Queries, then listens for a specified
 *   amount of time.  It then prints the source and destination of each message and
 *   related information for the particular multicast address.  The multicast address
 *   range information is taken from: http://www.iana.org/assignments/multicast-addresses/.
 *
 * Author: Vince Gibson, Georgia Tech Research Institute
 * Copyright: Georgia Tech Research Corporation, Copyright (C) 2010
 *
 * @see The GNU Public License (GPL)
 */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

 #include <gtk/gtk.h>

/* TreeItem structure */
typedef struct _TreeItem TreeItem;
struct _TreeItem
{
    gboolean        duplicate;
    gchar source[256];
    gchar sourcePort[256];
    gchar arrow[4];
    gchar destination[256];
    gchar destinationPort[256];
    gchar IANA[256];
};

#define MAX_MESSAGES 100
