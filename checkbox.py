import imaplib
import email
import re
import os


class MailBox:
    def __init__(self):

        self.server = None
        self.login = None
        self.password = None
        self.imap = None
        self.path = None
        self.status = None
        self.ids = None
        self.body_msg = None
        self.msg = None
        self.first_received_ip = None

    def sign_in(self):

        self.imap = imaplib.IMAP4_SSL(self.server)
        self.imap.login(self.login, self.password)

    def select_path(self, path):

        self.imap.list()
        self.imap.select(path)
        self.status, self.ids = self.imap.search(None, 'ALL')

    def choice_last_msg(self):

        list_ids = self.ids[0].split()
        last_msg = list_ids[-1]
        self.body_msg = self.imap.fetch(last_msg, '(RFC822)')

    def message_from_bytes(self):

        self.msg = email.message_from_bytes(self.body_msg[1][0][1])

    def find_first_received_ip(self):

        all_received = self.msg.get_all('Received')
        self.first_received_ip = re.findall(
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            all_received[-1]
        )

    def exit_form_mailbox(self):

        self.imap.close()
