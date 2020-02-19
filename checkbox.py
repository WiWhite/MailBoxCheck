import imaplib
import email
import re
import os

import ipwhois


class MailBox:
    """
    The class’s task is to login to the mail server and determine
    the real sender(IP address) of the mail message.
    """

    def __init__(self, server=None, login=None, password=None):

        self.server = server
        self.login = login
        self.password = password
        self.imap = None
        self.path = None
        self.status = None
        self.ids = None
        self.body_msg = None
        self.msg = None
        self.first_received_ip = None
        self.country_network = None
        self.all_received = None
        self.last_msg = None

    def sign_in(self):

        assert self.server, 'You did not pass the server value!'
        assert self.login, 'You did not pass the login value!'
        assert self.password, 'You did not pass the password value!'

        try:
            self.imap = imaplib.IMAP4_SSL(self.server)
            self.imap.login(self.login, self.password)
        except imaplib.IMAP4.error:
            print('Log in failed. Please, check you login and password.')

    @staticmethod
    def __choice_last_msg(ids):

        list_ids = ids[0].split()
        last_msg = list_ids[-1]

        return last_msg

    def select_path(self, path='INBOX'):

        """
        list()  List mailbox names in directory matching pattern.
        select() Select a mailbox
        search() Search mailbox for matching messages. Charset may be None, in
        which case no CHARSET will be specified in the request to the server.
        :param path: Select a mailbox, the default mailbox is 'INBOX'
        :return: status, ids messages
        """

        self.imap.list()
        self.imap.select(path)
        self.status, self.ids = self.imap.search(None, 'ALL')

    def message_from_bytes(self):

        self.last_msg = self.__choice_last_msg(self.ids)
        self.body_msg = self.imap.fetch(self.last_msg, '(RFC822)')
        self.msg = email.message_from_bytes(self.body_msg[1][0][1])

    @staticmethod
    def __get_whois_rdap(ip):

        """
        The function provides the sender country code.
        :param ip: ip address first received.
        :return: country code first received.
        """

        data = ipwhois.IPWhois(ip).lookup_rdap(
            asn_methods=['dns', 'whois', 'http'])

        if data['network']['country'] is None:
            data = data['asn_country_code']
        else:
            data = data['network']['country']

        return data

    def find_first_received_ip_and_country(self):

        """
        Get all Received and return first Received.
        Through RDAP finds the country code.
        """

        self.all_received = self.msg.get_all('Received')
        pattern_ipv4 = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        pattern_ipv6 = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|' \
                       r'([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}' \
                       r':){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:)' \
                       r'{1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:)' \
                       r'{1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:)' \
                       r'{1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:)' \
                       r'{1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:' \
                       r'((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4})' \
                       r'{1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]' \
                       r'{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|' \
                       r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]' \
                       r'|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}' \
                       r':){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])' \
                       r'\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

        try:
            self.first_received_ip = re.findall(
                pattern_ipv4, self.all_received[-1])[0]
            self.country_network = self.__get_whois_rdap(
                self.first_received_ip)

        except (IndexError, ipwhois.exceptions.IPDefinedError):
            self.first_received_ip = re.findall(
                pattern_ipv4, self.all_received[-2])[0]
            self.country_network = self.__get_whois_rdap(
                self.first_received_ip)

    def move_to_spam(self):

        """
        The method moves the last message to the trash and deletes it.
        """

        copy_res = self.imap.copy(self.last_msg, 'Trash')
        if copy_res[0] == 'OK':
            self.imap.store(self.last_msg, '+FLAGS', '\\Deleted')
            self.imap.expunge()

    def exit_form_mailbox(self):

        self.imap.close()
