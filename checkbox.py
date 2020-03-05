import imaplib
import email
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import re
import smtplib
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
        self.msg_string = None

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

    def select_path(self, path='INBOX', readonly=True):

        """
        list()  List mailbox names in directory matching pattern.
        select() Select a mailbox
        search() Search mailbox for matching messages. Charset may be None, in
        which case no CHARSET will be specified in the request to the server.
        :param readonly: if readonly is True, method don't delete msg
        :param path: Select a mailbox, the default mailbox is 'INBOX'
        :return: status, ids messages
        """

        self.imap.list()
        self.imap.select(path, readonly=readonly)
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

        if ip == '127.0.0.1':
            data = 'localhost'

        else:
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

        ipv4seg = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
        ipv4addr = r'(?:(?:' + ipv4seg + r'\.){3,3}' + ipv4seg + r')'
        ipv6seg = r'(?:(?:[0-9a-fA-F]){1,4})'
        ipv4_6groups = (
            r'(?:' + ipv6seg + r':){7,7}' + ipv6seg,
            r'(?:' + ipv6seg + r':){1,7}:',
            r'(?:' + ipv6seg + r':){1,6}:' + ipv6seg,
            r'(?:' + ipv6seg + r':){1,5}(?::' + ipv6seg + r'){1,2}',
            r'(?:' + ipv6seg + r':){1,4}(?::' + ipv6seg + r'){1,3}',
            r'(?:' + ipv6seg + r':){1,3}(?::' + ipv6seg + r'){1,4}',
            r'(?:' + ipv6seg + r':){1,2}(?::' + ipv6seg + r'){1,5}',
            ipv6seg + r':(?:(?::' + ipv6seg + r'){1,6})',
            r':(?:(?::' + ipv6seg + r'){1,7}|:)',
            r'fe80:(?::' + ipv6seg + r'){0,4}%[0-9a-zA-Z]{1,}',
            r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + ipv4addr,
            r'(?:' + ipv6seg + r':){1,4}:[^\s:]' + ipv4addr,
            ipv4addr
        )

        ipv4_6addr = '|'.join(['(?:{})'.format(g) for g in ipv4_6groups[::-1]])

        try:
            self.first_received_ip = re.findall(
                ipv4_6addr, self.all_received[-1])[0]
            self.country_network = self.__get_whois_rdap(
                self.first_received_ip)

        except (IndexError, ipwhois.exceptions.IPDefinedError):
            self.first_received_ip = re.findall(
                ipv4_6addr, self.all_received[-2])[0]
            self.country_network = self.__get_whois_rdap(
                self.first_received_ip)

    def move_to_spam(self):

        """
        The method moves the last message to the Junk and deletes it.
        """

        copy_res = self.imap.copy(self.last_msg, 'Junk')
        if copy_res[0] == 'OK':
            self.imap.store(self.last_msg, '+FLAGS', '\\Deleted')
            self.imap.expunge()

    def check_and_send_message(self, to, smtp_server, port=25):

        """
        This method performs three actions:
        - checks for the presence of a file in the message
        - creates a message to send
        - sends a message
        """

        file_name = self.__check_and_save_file(self.msg)

        msg = self.__create_msg(
            self.login,
            to,
            file_name,
            self.first_received_ip,
            self.country_network
        )

        self.__send_message(self.login, to, smtp_server, port, msg)

    @staticmethod
    def __create_msg(from_, to, filename, received_ip, country_network):

        """
        Creates a message to send.
        """

        msg = MIMEMultipart()
        msg['From'] = from_
        msg['To'] = to
        text = 'Real sender: {}\nCountry code: {}'.format(
            received_ip,
            country_network
        )

        try:
            with open(filename, 'rb') as file:
                content = MIMEApplication(file.read())
            content['Content-Disposition'] = \
                'attachment; filename={}'.format(filename)
            msg.attach(content)
            msg.attach(MIMEText(text))
            os.remove(filename)

        except TypeError:
            msg.attach(MIMEText(text))

        return msg

    @staticmethod
    def __send_message(
            from_,
            to,
            smtp_server,
            port,
            msg
    ):

        smtp = smtplib.SMTP(smtp_server, port)
        smtp.starttls()
        smtp.sendmail(
            from_,
            to,
            msg.as_string()
        )
        smtp.quit()

    @staticmethod
    def __check_and_save_file(msg):

        """
        Checks for the presence of a file in the message and save it.
        """

        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            file_name = part.get_filename()
            if bool(file_name):
                file_path = os.path.join(os.getcwd(), file_name)

                fp = open(file_path, 'wb')
                fp.write(part.get_payload(decode=True))
                fp.close()

            return file_name

    def exit_form_mailbox(self):

        self.imap.close()
