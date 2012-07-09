from xml.etree.ElementTree import Element
import socket
import time
import re

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup

# scraped from https://mxr.mozilla.org/mozilla-central/source/security/manager/ssl/src/nsIdentityChecking.cpp
# on 2012-07-08
mozilla_ev_oids = [
    '1.2.276.0.44.1.1.1.4',
    '1.2.392.200091.100.721.1',
    '1.2.40.0.17.1.22',
    '1.2.616.1.113527.2.5.1.1',
    '1.3.6.1.4.1.14370.1.6',
    '1.3.6.1.4.1.14777.6.1.1',
    '1.3.6.1.4.1.14777.6.1.2',
    '1.3.6.1.4.1.17326.10.14.2.1.2',
    '1.3.6.1.4.1.17326.10.8.12.1.2',
    '1.3.6.1.4.1.22234.2.5.2.3.1',
    '1.3.6.1.4.1.23223.2',
    '1.3.6.1.4.1.34697.2.1',
    '1.3.6.1.4.1.34697.2.2',
    '1.3.6.1.4.1.34697.2.3',
    '1.3.6.1.4.1.34697.2.4',
    '1.3.6.1.4.1.4146.1.1',
    '1.3.6.1.4.1.6334.1.100.1',
    '1.3.6.1.4.1.6449.1.2.1.5.1',
    '1.3.6.1.4.1.782.1.2.1.8.1',
    '1.3.6.1.4.1.8024.0.2.100.1.2',
    '2.16.578.1.26.1.3.3',
    '2.16.756.1.89.1.2.1.1',
    '2.16.840.1.113733.1.7.23.6',
    '2.16.840.1.113733.1.7.48.1',
    '2.16.840.1.114028.10.1.2',
    '2.16.840.1.114171.500.9',
    '2.16.840.1.114404.1.1.2.4.1',
    '2.16.840.1.114412.2.1',
    '2.16.840.1.114413.1.7.23.3',
    '2.16.840.1.114414.1.7.23.3',
]

class PluginEV(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginEV",
        description="Checks to see if certificates are EV")
    available_commands.add_command(
        command="ev",
        help="Help text for EV",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        ctSSL_initialize()
        cert = self._get_cert(target)

        ev = False
        cert_text = cert.as_text()
        try:
            policy = cert.get_extension_list().get_extension('X509v3 Certificate Policies')
            match = re.search(r'Policy:\s*([\d.]+)', policy)
            if match:
                oid = match.group(1)
                ev = oid in mozilla_ev_oids
        except KeyError:
            pass

        ctSSL_cleanup()

        # Text output
        cmd_title = 'EV Certificate'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        ev_txt = 'Certificate is an EV certificate' if ev \
                                             else 'Certificate is NOT an EV certificate'

        txt_result.append(output_format.format("EV:", ev_txt))

        # XML output
        xml_attr = { 'is_ev' : str(ev) }
        xml_el = Element('ev', attrib = xml_attr)

        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_el)

        return PluginBase.PluginResult(txt_result, xml_result)

    def _get_cert(self, target):
        """
        Connects to the target server and returns the server's certificate if
        the connection was successful.
        """
        ssl_connect = self._create_ssl_connection(target)
        ssl_connect.ssl_ctx.set_cipher_list(self.hello_workaround_cipher_list)

        try: # Perform the SSL handshake
            ssl_connect.connect()
            cert = ssl_connect.ssl.get_peer_certificate()
        finally:
            ssl_connect.close()

        return cert
