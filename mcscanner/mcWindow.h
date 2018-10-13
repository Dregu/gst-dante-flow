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
#ifndef GTKMM_MCWINDOW_H
#define GTKMM_MCWINDOW_H

#include <gtkmm.h>

class McWindow : public Gtk::Window
{
public:

    McWindow();
    void addMcData();
    virtual ~McWindow();
protected:
    //Signal handlers:
    virtual void on_button_quit();
    virtual void on_treeview_row_activated(const Gtk::TreeModel::Path& path, Gtk::TreeViewColumn *column);

    //Tree model columns:
    class ModelColumns : public Gtk::TreeModel::ColumnRecord
    {
    public:
        ModelColumns()
        {
            add(m_col_Duplicate);
            add(m_col_IP_Source);
            add(m_col_arrow);
            add(m_col_IP_Destination);
            add(m_col_IANA);
        }
        Gtk::TreeModelColumn<Glib::ustring> m_col_Duplicate;
        Gtk::TreeModelColumn<Glib::ustring> m_col_IP_Source;
        Gtk::TreeModelColumn<Glib::ustring> m_col_arrow;
        Gtk::TreeModelColumn<Glib::ustring> m_col_IP_Destination;
        Gtk::TreeModelColumn<Glib::ustring> m_col_IANA;
    };
    ModelColumns m_Columns;
    //Child widgets:
    Gtk::VBox m_VBox;
    Gtk::ScrolledWindow m_ScrolledWindow;
    Gtk::TreeView m_TreeView;
    Glib::RefPtr<Gtk::TreeStore> m_refTreeModel;
    Gtk::HButtonBox m_ButtonBox;
    Gtk::Button m_Button_Quit;
};
#endif //GTKMM_MCWINDOW_H
