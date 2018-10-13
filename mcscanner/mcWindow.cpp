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

/*
//
// NOTE: Some of the gtk and gtkmm code was taken from various examples on the Internet.
//
*/

#include <iostream>
#include "mcWindow.h"
#include "gtkMcScanner.h"


extern int gError;

/* tree data */
TreeItem gTempMcListIGMP[MAX_MESSAGES];
TreeItem gTempMcList[MAX_MESSAGES];

extern int gIgmpCount;
extern int gOthersCount;

/* columns */
enum
{
    DUPLICATE_COLUMN = 0,
    SOURCE_COLUMN,
    ARROW_COLUMN,
    DESTINATION_COLUMN,
    IANA_COLUMN,
    NUM_COLUMNS
};

McWindow::~McWindow()
{
}

void McWindow::on_button_quit()
{
    hide();
}

void McWindow::on_treeview_row_activated(const Gtk::TreeModel::Path& path,
        Gtk::TreeViewColumn* /* column */)
{
    Gtk::TreeModel::iterator iter = m_refTreeModel->get_iter(path);
    if(iter)
    {
        Gtk::TreeModel::Row row = *iter;
        std::cout << "Row activated: Dup = " << row[m_Columns.m_col_Duplicate]
        << ", Source = " << row[m_Columns.m_col_IP_Source]
        << ", Destination = " << row[m_Columns.m_col_IP_Destination]
        << ", IANA = " << row[m_Columns.m_col_IANA]
        << std::endl;
    }
}

McWindow::McWindow()
    : m_Button_Quit("Quit")
{
    set_title("gtkmm McScanner");
    set_border_width(5);
    set_default_size(800, 600);
    add(m_VBox);
    m_ScrolledWindow.add(m_TreeView);
    m_ScrolledWindow.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
    m_VBox.pack_start(m_ScrolledWindow);
    m_VBox.pack_start(m_ButtonBox, Gtk::PACK_SHRINK);
    m_ButtonBox.pack_start(m_Button_Quit, Gtk::PACK_SHRINK);
    m_ButtonBox.set_border_width(5);
    m_ButtonBox.set_layout(Gtk::BUTTONBOX_END);
    m_Button_Quit.signal_clicked().connect(sigc::mem_fun(*this, &McWindow::on_button_quit) );
    m_refTreeModel = Gtk::TreeStore::create(m_Columns);
    m_TreeView.set_model(m_refTreeModel);
    //m_TreeView.set_reorderable();

    m_TreeView.append_column("Duplicate", m_Columns.m_col_Duplicate);
    m_TreeView.append_column("IP Source: Port", m_Columns.m_col_IP_Source);
    m_TreeView.append_column("  ", m_Columns.m_col_arrow);
    m_TreeView.append_column("IP Destination: Port", m_Columns.m_col_IP_Destination);
    m_TreeView.append_column("IANA", m_Columns.m_col_IANA);
    m_TreeView.signal_row_activated().connect(sigc::mem_fun(*this, &McWindow::on_treeview_row_activated) );

}

void McWindow::addMcData()
{
    m_refTreeModel->clear();

    TreeItem *multicast;

    Gtk::TreeModel::Row row = *(m_refTreeModel->append());

    if(gError)
    {

        row[m_Columns.m_col_Duplicate] = "";
        row[m_Columns.m_col_IP_Source] = "ERROR! Check Console!";
    }
    else
    {
        row[m_Columns.m_col_Duplicate] = "";
        row[m_Columns.m_col_IP_Source] = "Publishers";

        multicast = &gTempMcList[0];
        if(gOthersCount > MAX_MESSAGES)
        {
            gOthersCount = MAX_MESSAGES;
            printf("ERROR: Increase MAX_MESSAGES\n");
        }
        for(int v=0; v<gOthersCount; v++)
        {
            /* add children */
            Gtk::TreeModel::Row childrow = *(m_refTreeModel->append(row.children()));
            if(multicast->duplicate)
                childrow[m_Columns.m_col_Duplicate] = "*";
            else
                childrow[m_Columns.m_col_Duplicate] = "";
            childrow[m_Columns.m_col_IP_Source] = multicast->source;
            childrow[m_Columns.m_col_arrow] = "->";
            childrow[m_Columns.m_col_IP_Destination] = multicast->destination;
            childrow[m_Columns.m_col_IANA] = multicast->IANA;

            multicast++;
        }
    }

    row = *(m_refTreeModel->append());
    if(gError)
    {
        row[m_Columns.m_col_Duplicate] = "";
        row[m_Columns.m_col_IP_Source] = "Try sudo.";
    }
    else
    {
        row[m_Columns.m_col_Duplicate] = "";
        row[m_Columns.m_col_IP_Source] = "Subscribers";

        if(gIgmpCount > MAX_MESSAGES)
        {
            gIgmpCount = MAX_MESSAGES;
            printf("ERROR: Increase MAX_MESSAGES\n");
        }

        multicast = &gTempMcListIGMP[0];
        for(int v=0; v<gIgmpCount; v++)
        {
            /* add children */
            Gtk::TreeModel::Row childrow = *(m_refTreeModel->append(row.children()));
            if(multicast->duplicate)
                childrow[m_Columns.m_col_Duplicate] = "*";
            else
                childrow[m_Columns.m_col_Duplicate] = "";
            childrow[m_Columns.m_col_IP_Source] = multicast->source;
            childrow[m_Columns.m_col_arrow] = "->";
            childrow[m_Columns.m_col_IP_Destination] = multicast->destination;
            childrow[m_Columns.m_col_IANA] = multicast->IANA;

            multicast++;
        }
    }

    show_all_children();

    m_TreeView.expand_all();

}









