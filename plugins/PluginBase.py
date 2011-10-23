#-------------------------------------------------------------------------------
# Name:         PluginBase.py
# Purpose:      Main abstract plugin class. All the actual plugins are
#               subclasses of PluginBase.
#
# Author:       aaron, alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
# Licence:      Licensed under the terms of the GPLv2 License
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import abc


class AvailableCommands:
    """
    This object tells the main process which command line option(s)
    a plugin implements. Every plugin should have a class attribute called
    available_commands that is an instance of AvailableCommands.
    """

    def __init__(self, title, description):
        """
        Title and description are sent to optparse.OptionGroup().
        """
        self.title = title
        self.description = description
        self.options = []

    def add_option(self, command, help, dest):
        """
        Command and help are sent to optparse.OptionGroup.add_option().
        Note: dest to None if you don't need arguments
        """
        self.options.append( (command, help, dest) )


class PluginBase(object):
    """
    Base plugin abstract class. All plugins have to inherit from it.
    """
    __metaclass__ = abc.ABCMeta


    def  __init__(self, shared_state):
        """
        Plugin constructor. Initializes self.shared_state, which contains
        read-only info available to all the plugins: client certificate, timeout
        value, etc...
        """
        self._shared_state = shared_state #TODO: Document what's in shared_state
        return


    def get_commands(plugin_class):
        """
        This method returns the AvailableCommands object for the current plugin.
        """
        return plugin_class.available_commands
    get_commands = classmethod(get_commands)


    @abc.abstractmethod
    def process_task(self, target, command, args):
        """
        This method should implement what the plugin is expected to do / test
        when given a target=(host, ip_addr, port), a command line option, and
        a command line argument. It has to be defined in each plugin class.
        """
        return
