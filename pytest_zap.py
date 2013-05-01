import glob
from xml.dom.minidom import parse
from ConfigParser import SafeConfigParser
import copy
import zipfile
import logging
import os
import platform
import subprocess
import time
import urllib

import py
from zapv2 import ZAPv2

__version__ = '0.1'

def pytest_addoption(parser):
    group = parser.getgroup('zap', 'zap')
    group._addoption('--zap-interactive',
        action='store_true',
        dest='zap_interactive',
        default=False,
        help='run zap in interactive mode. (default: %default)')
    group._addoption('--zap-path',
        action='store',
        dest='zap_path',
        metavar='path',
        help='location of zap installation.')
    group._addoption('--zap-log',
        action='store',
        dest='zap_log',
        default='zap.log',
        metavar='path',
        help='location of zap log file. (default %default)')
    group._addoption('--zap-home',
        action='store',
        dest='zap_home',
        metavar='path',
        help='location of zap home directory.')
    group._addoption('--zap-config',
        action='store',
        dest='zap_config',
        default='zap.cfg',
        metavar='path',
        help='location of zap configuration file. (default: %default)')
    group._addoption('--zap-host',
        action='store',
        dest='zap_host',
        default='localhost',
        metavar='str',
        help='host zap is listening on. (default: %default)')
    group._addoption('--zap-port',
        action='store',
        dest='zap_port',
        metavar='int',
        default=8080,
        type='int',
        help='port zap is listening on. (default: %default)')
    group._addoption('--zap-target',
        action='store',
        dest='zap_target',
        metavar='url',
        help='target url for spider and scan.')
    group._addoption('--zap-exclude',
        action='store',
        dest='zap_exclude',
        metavar='str',
        help='exclude urls matching this regex when scanning.')
    group._addoption('--zap-spider',
        action='store_true',
        dest='zap_spider',
        default=False,
        help='spider the target. (default: %default)')
    group._addoption('--zap-scan',
        action='store_true',
        dest='zap_scan',
        default=False,
        help='scan the target. (default: %default)')
    group._addoption('--zap-save',
        action='store_true',
        dest='zap_save_session',
        default=False,
        help='save the zap session in zap.session within home directory. (default: %default)')
    group._addoption('--zap-load',
        action='store',
        dest='zap_load_session',
        metavar='path',
        help='location of an archived zap session to open.')
    group._addoption('--zap-ignore',
        action='store',
        dest='zap_ignore',
        default='zap_ignore.txt',
        metavar='path',
        help='location of ignored alerts text file. (default: %default)')
    group._addoption('--zap-skip-tests',
        action='store_true',
        dest='zap_skip_tests',
        default=False,
        help='skip all tests')
    #TODO Add observation mode to prevent failing when alerts are raised


def pytest_configure(config):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler('%s.log' % __name__, 'w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    config._zap_config = SafeConfigParser()
    config._zap_config.read(config.option.zap_config)

    config.option.zap_target = config.option.zap_target or \
                               (hasattr(config.option, 'base_url') and config.option.base_url)


#TODO Use py.test fixtures
#See http://pytest.org/latest/fixture.html
def pytest_sessionstart(session):
    logger = logging.getLogger(__name__)
    if hasattr(session.config, 'slaveinput') or session.config.option.collectonly:
        return

    zap_url = 'http://%s:%s' % (session.config.option.zap_host, session.config.option.zap_port)
    proxies = {'http': zap_url, 'https': zap_url}

    if not session.config._zap_config.has_option('control', 'start') or\
       session.config._zap_config.getboolean('control', 'start'):
        if platform.system() == 'Windows':
            zap_script = ['start /b zap.bat']
        else:
            zap_script = ['./zap.sh']

        if not session.config.option.zap_interactive:
            # Run as a daemon
            zap_script.append('-daemon')

        zap_script.append('-port %s' % session.config.option.zap_port)

        #TODO Support user directory for ZAP path
        zap_path = session.config.option.zap_path
        if not zap_path:
            if platform.system() == 'Windows':
                # Win 7 default path
                zap_path = 'C:\Program Files (x86)\OWASP\Zed Attack Proxy'
                if not os.path.exists(zap_path):
                    # Win XP default path
                    zap_path = "C:\Program Files\OWASP\Zed Attack Proxy"
            else:
                message = 'Installation directory must be set using --zap-path command line option'
                logger.error(message)
                raise Exception(message)

        #TODO Support user directory for ZAP home
        zap_home = session.config.option.zap_home and\
                   os.path.abspath(session.config.option.zap_home) or\
                   os.path.join(zap_path, 'home')
        session.config.option.zap_home = zap_home

        if not os.path.exists(zap_home):
            logger.info('Creating home directory in %s' % zap_home)
            os.makedirs(zap_home)

        license_path = os.path.join(zap_home, 'AcceptedLicense')
        if not os.path.exists(license_path):
            # Create a blank accepted license file, otherwise will be prompted for
            logger.info('Creating blank license file in %s' % license_path)
            license_file = open(license_path, 'w')
            license_file.close()

        # Create config.xml file
        #TODO Move to method?
        config_path = os.path.join(zap_home, 'config.xml')
        default_config_path = os.path.join(zap_path, 'xml', 'config.xml')
        base_config_path = os.path.exists(config_path) and\
                           os.path.getsize(config_path) > 0 and\
                           config_path or\
                           default_config_path

        logger.info('Using configuration from %s' % base_config_path)
        document = parse(base_config_path)
        config = document.getElementsByTagName('config')[0]

        # Set user directory
        user_dir = config.getElementsByTagName('userDir')[0]
        if user_dir.hasChildNodes():
            user_dir.replaceChild(
                document.createTextNode(zap_home),
                user_dir.firstChild)
        else:
            user_dir.appendChild(document.createTextNode(zap_home))

        if session.config.option.zap_interactive:
            # Enable API
            enabled = document.createElement('enabled')
            enabled.appendChild(document.createTextNode('true'))
            api = document.createElement('api')
            api.appendChild(enabled)
            config.appendChild(api)

            # Disable update checking
            start = config.getElementsByTagName('start')[0]
            check_for_updates = document.createElement('checkForUpdates')
            check_for_updates.appendChild(document.createTextNode('0'))
            start.appendChild(check_for_updates)
            day_last_checked = document.createElement('dayLastChecked')
            day_last_checked.appendChild(document.createTextNode('Never'))
            start.appendChild(day_last_checked)

        # Set proxy
        proxy = config.getElementsByTagName('proxy')[0]
        ip = proxy.getElementsByTagName('ip')[0]
        ip.replaceChild(
            document.createTextNode(session.config.option.zap_host),
            ip.firstChild)

        logger.info('Writing configuration to %s' % config_path)
        config_file = open(config_path, 'w')
        document.writexml(config_file)
        config_file.close()

        zap_script.extend(['-dir', zap_home])

        logger.info('Starting ZAP')
        #TODO Move all launcher code to Python client
        logger.info('Running %s' % ' '.join(zap_script))
        logger.info('From %s' % zap_path)

        # Check if ZAP is already running
        if is_zap_running(zap_url):
            message = 'ZAP is already running'
            logger.error(message)
            raise Exception(message)

        # Start ZAP
        session.config.log_file = open(os.path.expanduser(session.config.option.zap_log), 'w')
        #TODO catch exception on launching (for example Java version issue)
        session.config.zap_process = subprocess.Popen(zap_script,
                                                      cwd=zap_path,
                                                      stdout=session.config.log_file,
                                                      stderr=subprocess.STDOUT)
        try:
            wait_for_zap_to_start(zap_url)
            session.config.zap = ZAPv2(proxies=proxies)
        except:
            kill_zap_process(session.config.zap_process)
            raise
    else:
        # Check if ZAP is already running
        logger.info('Connecting to existing ZAP instance at %s' % zap_url)
        if not is_zap_running(zap_url):
            message = 'ZAP is not running'
            logger.error(message)
            raise Exception(message)
        session.config.zap = ZAPv2(proxies=proxies)

    # Save session
    if session.config.option.zap_save_session:
        session_path = os.path.join(os.path.abspath(session.config.option.zap_home), 'zap')
        logger.info('Saving session in %s' % session_path)

        if not session.config.option.zap_home:
            logger.error('Home directory must be set using --zap-home command line option')

        session.config.zap.core.save_session(session_path)
    else:
        logger.info('Skipping save session')

    logger.info('Generating a root CA certificate')
    #TODO Change this to a function call
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=572
    session.config.zap.core.generate_root_ca

    if session.config.option.zap_load_session:
        try:
            #TODO Remove this when the archived sessions are supported by default
            # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=373
            load_session_zip_path = os.path.expanduser(session.config.option.zap_load_session)
            logger.info('Extracting session from %s' % load_session_zip_path)
            load_session_zip = zipfile.ZipFile(load_session_zip_path)
            load_session_path = os.path.abspath(os.path.join(session.config.option.zap_home, 'load_session'))
            load_session_zip.extractall(load_session_path)
            load_session_file = glob.glob(os.path.join(load_session_path, '*.session'))[0]
            logger.info('Loading session from %s' % load_session_file)
            session.config.zap.core.load_session(load_session_file)
        except (IOError, zipfile.BadZipfile) as e:
            logger.error('Failed to load session. %s' % e)
            kill_zap_process(session.config.zap_process)
            raise


def pytest_runtest_setup(item):
    if item.config.option.zap_skip_tests:
        py.test.skip()


def pytest_sessionfinish(session):
    logger = logging.getLogger(__name__)
    if hasattr(session.config, 'slaveinput') or session.config.option.collectonly:
        return

    print '\n'
    zap = session.config.zap

    # Passive scan
    wait_for_passive_scan(zap)

    zap_urls = copy.deepcopy(zap.core.urls)
    logger.info('Got %s URLs' % len(zap_urls))

    # Spider
    if session.config.option.zap_spider and session.config.option.zap_target:
        if session.config.option.zap_exclude:
            zap.spider.exclude_from_scan(session.config.option.zap_exclude)
        logger.info('Spider progress: 0%')
        zap.spider.scan(session.config.option.zap_target)
        status = int(zap.spider.status)
        while status < 100:
            new_status = int(zap.spider.status)
            if new_status > status:
                level = logging.INFO
                status = new_status
            else:
                level = logging.DEBUG
            logger.log(level, 'Spider progress: %s%%' % new_status)
            time.sleep(5)
        logger.info('Spider progress: 100%')
        #TODO API call for new URLs discovered by spider
        # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=368
        new_urls = copy.deepcopy(zap.core.urls)
        logger.info('Spider found %s additional URLs' % (len(new_urls) - len(zap_urls)))
        wait_for_passive_scan(zap)
    else:
        logger.info('Skipping spider')

    zap_alerts = get_alerts(zap)

    # Active scan
    if session.config.option.zap_scan and session.config.option.zap_target:
        if session.config.option.zap_exclude:
            zap.ascan.exclude_from_scan(session.config.option.zap_exclude)
        logger.info('Scan progress: 0%')
        zap.ascan.scan(session.config.option.zap_target)
        status = int(zap.ascan.status)
        while status < 100:
            new_status = int(zap.ascan.status)
            if new_status > status:
                level = logging.INFO
                status = new_status
            else:
                level = logging.DEBUG
            logger.log(level, 'Scan progress: %s%%' % new_status)
            time.sleep(5)
        logger.info('Scan progress: 100%')
        zap_alerts.extend(get_alerts(zap, start=len(zap_alerts)))
    else:
        logger.info('Skipping scan')

    # Filter alerts
    ignored_alerts = []
    alerts = []
    if zap_alerts and os.path.exists(session.config.option.zap_ignore):
        with open(session.config.option.zap_ignore, 'r') as f:
            zap_ignores = f.readlines()
        for alert in zap_alerts:
            if '%s\n' % alert['alert'] in zap_ignores:
                ignored_alerts.append(alert)
            else:
                alerts.append(alert)
        if ignored_alerts:
            for alert in set(['%s [%s]' % (i['alert'], i['risk']) for i in ignored_alerts]):
                logger.info('Ignored alert: %s' % alert)
    else:
        alerts.extend(zap_alerts)

    if alerts:
        for alert in set(['%s [%s]' % (i['alert'], i['risk']) for i in alerts]):
            logger.warn('Alert: %s' % alert)

    #TODO Save alerts report
    #TODO Save JUnit style report
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=371
    #TODO Save URLs report
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=368

    if not session.config._zap_config.has_option('control', 'stop') or\
        session.config._zap_config.getboolean('control', 'stop'):
        logger.info('Stopping ZAP')
        try:
            zap.core.shutdown()
        except:
            pass
        try:
            zap_url = 'http://%s:%s' % (session.config.option.zap_host, session.config.option.zap_port)
            wait_for_zap_to_stop(zap_url)
        except:
            if hasattr(session.config, 'zap_process'):
                kill_zap_process(session.config.zap_process)

    # Close log file
    if hasattr(session.config, 'log_file'):
        session.config.log_file.close()

    # Archive session
    #TODO Remove this when the session is archived by default
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=373
    if session.config.option.zap_save_session:
        wait_for_lock_file_removed(os.path.join(session.config.option.zap_home, 'zap.session.lck'))
        session_files = glob.glob(os.path.join(session.config.option.zap_home, 'zap.session*'))
        if len(session_files) > 0:
            #TODO Use compression
            session_zip = zipfile.ZipFile(os.path.join(session.config.option.zap_home, 'zap_session.zip'), 'w')
            for session_file in session_files:
                session_zip.write(session_file, session_file.rpartition(os.path.sep)[2])
            session_zip.close()
            logger.info('Session archived in %s' % session_zip.filename)
        else:
            logger.warn('No session files to archive')

    #TODO Fail if alerts were raised (unless in observation mode)


def get_alerts(api, start=0):
    logger = logging.getLogger(__name__)
    alerts_per_request = 1000
    alerts = []
    while True:
        logger.info('Getting alerts: %s-%s' % (start, (start + alerts_per_request)))
        new_alerts = api.core.alerts(start=start, count=alerts_per_request).get('alerts')
        alerts.extend(new_alerts)
        if len(new_alerts) == alerts_per_request:
            start += alerts_per_request
        else:
            logger.info('Got %s alerts' % len(alerts))
            return alerts


def is_zap_running(url):
    logger = logging.getLogger(__name__)
    try:
        proxies = {'http': url, 'https': url}
        response = urllib.urlopen('http://zap/', proxies=proxies)
        if 'ZAP-Header' in response.headers.get('Access-Control-Allow-Headers', []):
            return True
        else:
            message = 'Service running at %s is not ZAP' % url
            logger.error(message)
            raise Exception(message)
    except IOError:
        return False


def wait_for_passive_scan(api):
    logger = logging.getLogger(__name__)
    logger.info('Waiting for passive scan')
    logger.info('Records to scan: %s' % api.pscan.records_to_scan)
    while int(api.pscan.records_to_scan) > 0:
        time.sleep(5)
        logger.info('Records to scan: %s' % api.pscan.records_to_scan)
    logger.info('Finished passive scan')


def wait_for_lock_file_removed(path):
    logger = logging.getLogger(__name__)
    timeout = 60
    end_time = time.time() + timeout
    while os.path.exists(path):
        time.sleep(1)
        if time.time() > end_time:
            message = 'Timeout after %s seconds waiting for lock file to be removed: %s' % (timeout, path)
            logger.error(message)
            raise Exception(message)


def wait_for_zap_to_start(url):
    logger = logging.getLogger(__name__)
    logger.info('Waiting for ZAP to start')
    timeout = 60
    end_time = time.time() + timeout
    while not is_zap_running(url):
        time.sleep(1)
        if time.time() > end_time:
            message = 'Timeout after %s seconds waiting for ZAP' % timeout
            logger.error(message)
            raise Exception(message)
    logger.info('ZAP has successfully started')


def wait_for_zap_to_stop(url):
    logger = logging.getLogger(__name__)
    logger.info('Waiting for ZAP to shutdown')
    timeout = 60
    end_time = time.time() + timeout
    while is_zap_running(url):
        time.sleep(1)
        if time.time() > end_time:
            message = 'Timeout after %s seconds waiting for ZAP to shutdown' % timeout
            logger.error(message)
            raise Exception(message)
    logger.info('ZAP has successfully shutdown')


def kill_zap_process(process):
    logger = logging.getLogger(__name__)
    try:
        process.kill()
    except:
        logger.error('Unable to kill ZAP process')
