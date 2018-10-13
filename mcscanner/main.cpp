/*
 * Project: gtkMcScanner - Multicast Network Scanner
 * File name: main.c
 * Description:  This program (gtkMcScanner) scans a network for multicast sources and traffic,
 *   which are explicitly avoided in typical network scanners such as nmap.
 *   The program sends PIM Hello and IGMP Queries, then listens for a specified
 *   amount of time.  It then displays the source and destination of each message and
 *   related information for the particular multicast address.  The multicast address
 *   range information is taken from: http://www.iana.org/assignments/multicast-addresses/.
 *   If a duplicate group is detected, it will checked on the display.
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

#include <gtkmm.h>
#include <semaphore.h>
#include "gtkMcScanner.h"
#include "mcWindow.h"

GtkTreeStore *gTreeModel;
GtkTreeView *gTreeview;

sem_t gDisplayLock;

int gError = 0;

extern "C" int runScan(void);

// starts the scan process
void pcapTimerCallback(union sigval  arg)
{
    if(runScan() == 2)
        gError = 1;
}

int setPcapTimer (time_t delay)
{
    struct sigevent se;
    struct itimerspec ts;
    struct itimerspec tso;
    timer_t timerid;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = &timerid;
    se.sigev_notify_function = pcapTimerCallback;
    se.sigev_notify_attributes = NULL;

    if (-1 == timer_create(CLOCK_REALTIME, &se, &timerid))
    {
        perror("timer_create:");
        return(1);
    }

    ts.it_value.tv_sec = delay;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    if (-1 == timer_settime(timerid, 0, &ts, &tso))
    {
        perror("timer_settime:");
        return(1);
    }

    return 0;
}

static gpointer gtkDisplay( gpointer data )
{
    McWindow* ptr = (McWindow*)data;
    while( TRUE )
    {
        sleep( 1 );
        sem_wait(&gDisplayLock);
        gdk_threads_enter();
        ptr->addMcData();
        gdk_threads_leave();
        sem_post(&gDisplayLock);
    }

    return( NULL );
}

int main( int   argc,
          char *argv[] )
{
    GError    *error = NULL;
    GThread   *thread;

    Gtk::Main kit(argc, argv);

    McWindow window;
    McWindow *winPtr = &window;


    if( ! g_thread_supported() )
        g_thread_init( NULL );

    /* control access to the tree */
    sem_init(&gDisplayLock,0,1);

    gdk_threads_init();

    gdk_threads_enter();

    /* start display thread */
    thread = g_thread_create( gtkDisplay, winPtr,
                              FALSE, &error );
    if( ! thread )
    {
        g_print( "Error: %s\n", error->message );
        return( -1 );
    }

    /* start pcap thread */
    setPcapTimer(1);

    //Shows the window and returns when it is closed.
    Gtk::Main::run(window);

    /* Release gtk's global lock */
    gdk_threads_leave();

    sem_destroy(&gDisplayLock);

    return 0;
}

