#{{{ License header: MIT
# Copyright (c) 2016 Till Maas <opensource@till.name>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#}}}

# Burp extension to add a context menu to ignore hostnames
import inspect
import os
import re
import sys

import java.util
# from java.io import PrintWriter
from javax.swing import JMenuItem
from java.awt.event import ActionListener

from burp import IBurpExtender
from burp import IContextMenuFactory

currentfile = inspect.getfile(inspect.currentframe())
sys.path.insert(0, os.path.dirname(os.path.abspath(currentfile)))
from burp_config import ScopeList


class ContextMenuFactory(IContextMenuFactory, ActionListener):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.invocation = None
        self.messages = []
        self.drop_item = None

    def createMenuItems(self, invocation):
        """
        :parameter:invocation: IContextMenuInvocation()

        :returns: None if menu is not appropriate here, else list of JMenuItem
        is returned
        """

        self.invocation = invocation
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        self.messages = messages
        if len(messages) > 1:
            plural = "s"
        else:
            plural = ""
        menu_items = []
        description = "Exclude host{} from scope".format(plural)
        exclude_item = JMenuItem(description)
        menu_items.append(exclude_item)

        self.drop_item = JMenuItem(description + " (and drop requests)")
        menu_items.append(self.drop_item)
        for item in menu_items:
            item.addActionListener(self)

        # stdout = PrintWriter(self.callbacks.getStdout(), True)
        return menu_items

    def actionPerformed(self, event):
        # stdout = PrintWriter(self.callbacks.getStdout(), True)
        hosts = set()
        for message in self.messages:
            httpservice = message.getHttpService()
            host = httpservice.getHost()
            host = re.escape(host)
            hosts.add(host)

        def add_to_scopelist(prefix, config=None):
            if config is None:
                burp_config = self.callbacks.saveConfig()
                config = {}
                for entry in burp_config.entrySet():
                    config[entry.key] = entry.value

            scope_list = ScopeList(prefix=prefix)
            remaining_config = scope_list.parse(config)
            for host in hosts:
                scope_list.exclude_host(host)
            encoded_list = scope_list.encode()
            remaining_config.update(encoded_list)
            return remaining_config

        config = None
        if event.getSource() == self.drop_item:
            config = add_to_scopelist("target.droprequestsscope", config)
        config = add_to_scopelist("target.scope", config)

        new_burp_config = java.util.HashMap()
        for key, value in sorted(config.items()):
            # stdout.println("Setting: " + repr(key) + "." + repr(value))
            new_burp_config[key] = value
        self.callbacks.loadConfig(new_burp_config)


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Scoper")

        callbacks.registerContextMenuFactory(ContextMenuFactory(callbacks))
