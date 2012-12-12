import glob
from xml.dom.minidom import parse
from ConfigParser import SafeConfigParser
import copy
import zipfile
import os
import platform
import subprocess
import sys
import time
import urllib

from zap import ZAP

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
        metavar='str',
        help='host zap is listening on. (default: localhost)')
    group._addoption('--zap-port',
        action='store',
        dest='zap_port',
        type='int',
        help='port zap is listening on. (default: 8080)')
    group._addoption('--zap-target',
        action='store',
        dest='zap_target',
        metavar='url',
        help='target url for spider and scan.')
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
    group._addoption('--zap-save-session',
        action='store_true',
        dest='zap_save_session',
        default=False,
        help='save the zap session in zap.session within home directory. (default: %default)')
    group._addoption('--zap-ignore',
        action='store',
        dest='zap_ignore',
        default='zap_ignore.txt',
        metavar='path',
        help='location of ignored alerts text file. (default: %default)')
    group._addoption('--zap-cert',
        action='store',
        dest='zap_cert',
        default='zap.cert',
        metavar='path',
        help='location of ssl certificate. (default: %default)')
    #TODO Add observation mode to prevent failing when alerts are raised


def pytest_configure(config):
    config._zap_config = SafeConfigParser()
    config._zap_config.read(config.option.zap_config)

    config.option.zap_host = config.option.zap_host or\
                             (hasattr(config.option, 'proxy_host') and config.option.proxy_host) or\
                             'localhost'
    config.option.zap_port = config.option.zap_port or\
                             (hasattr(config.option, 'proxy_port') and config.option.proxy_port) or\
                             8080
    config.option.zap_target = config.option.zap_target or\
                               (hasattr(config.option, 'base_url') and config.option.base_url)


def pytest_sessionstart(session):
    if hasattr(session.config, 'slaveinput') or session.config.option.collectonly:
        return

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

        zap_path = session.config.option.zap_path
        if not zap_path:
            if platform.system() == 'Windows':
                # Win 7 default path
                zap_path = 'C:\Program Files (x86)\OWASP\Zed Attack Proxy'
                if not os.path.exists(zap_path):
                    # Win XP default path
                    zap_path = "C:\Program Files\OWASP\Zed Attack Proxy"
            else:
                raise Exception('Installation directory must be set using --zap-path command line option.')

        zap_home = session.config.option.zap_home and\
                   os.path.abspath(session.config.option.zap_home) or\
                   os.sep.join([zap_path, 'home'])
        session.config.option.zap_home = zap_home

        if not os.path.exists(zap_home):
            os.makedirs(zap_home)

        license_path = os.sep.join([zap_home, 'AcceptedLicense'])
        if not os.path.exists(license_path):
            # Create a blank accepted license file, otherwise will be prompted for
            license_file = open(license_path, 'w')
            license_file.close()

        # Create config.xml file
        #TODO Move to method?
        config_path = os.sep.join([zap_home, 'config.xml'])
        default_config_path = os.sep.join([zap_path, 'xml', 'config.xml'])
        base_config_path = os.path.exists(config_path) and config_path or default_config_path

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
            check_for_updates = start.getElementsByTagName('checkForUpdates')[0]
            check_for_updates.replaceChild(
                document.createTextNode("0"),
                check_for_updates.firstChild)
            day_last_checked = document.createElement('dayLastChecked')
            day_last_checked.appendChild(document.createTextNode('never'))
            start.appendChild(day_last_checked)

        # Set proxy
        proxy = config.getElementsByTagName('proxy')[0]
        ip = proxy.getElementsByTagName('ip')[0]
        ip.replaceChild(
            document.createTextNode(session.config.option.zap_host),
            ip.firstChild)

        # Add certificate
        #TODO Set certificate via the API
        # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=372
        if os.path.exists(session.config.option.zap_cert):
            with open(session.config.option.zap_cert,'r') as f:
                zap_cert = f.read()
            rootca = document.createElement('rootca')
            rootca.appendChild(document.createTextNode(zap_cert))
            param = document.createElement('param')
            param.appendChild(rootca)
            dynssl = document.createElement('dynssl')
            dynssl.appendChild(param)
            config.appendChild(dynssl)
        #TODO If certificate is not provided then generate one via the API
        # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=372

        config_file = open(config_path, 'w')
        document.writexml(config_file)
        config_file.close()

        zap_script.extend(['-dir', zap_home])

        print '\nStarting ZAP\n'
        #TODO Move all launcher code to Python client
        print 'Running: %s\nFrom: %s\n' % (' '.join(zap_script), zap_path)
        session.config.zap_process = subprocess.Popen(zap_script, cwd=zap_path, stdout=subprocess.PIPE)
        #TODO If launching, check that ZAP is not currently running?
        #TODO Support opening a saved session
        timeout = 60
        end_time = time.time() + timeout
        while(True):
            try:
                zap_url = 'http://%s:%s' % (session.config.option.zap_host,
                                            session.config.option.zap_port)
                proxies = {'http': zap_url,
                           'https': zap_url}
                status = urllib.urlopen('http://zap/', proxies=proxies).getcode()
                if status == 200:
                    break
            except IOError:
                pass
            time.sleep(1)
            if(time.time() > end_time):
                raise Exception('Timeout after %s seconds waiting for ZAP.' % timeout)


def pytest_sessionfinish(session):
    if hasattr(session.config, 'slaveinput') or session.config.option.collectonly:
        return

    print '\n'
    zap_url = 'http://%s:%s' % (session.config.option.zap_host,
                                session.config.option.zap_port)
    zap = ZAP(proxies={'http': zap_url, 'https': zap_url})
    #TODO Wait for passive scanner to finish
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=367
    print 'Waiting for passive scanner to finish'
    time.sleep(10)  # Give the passive scanner a chance to finish

    # Spider
    if session.config.option.zap_spider and session.config.option.zap_target:
        zap_urls = copy.deepcopy(zap.urls)
        print '\rSpider progress: 0%',
        zap.urlopen(session.config.option.zap_target)
        time.sleep(2)  # Give the sites tree a chance to get updated
        zap.start_spider(session.config.option.zap_target)
        while int(zap.spider_status[0]) < 100:
            print '\rSpider progress: %s%%' % zap.spider_status[0],
            sys.stdout.flush()
            time.sleep(1)
        print '\rSpider progress: 100%'
        #TODO API call for new URLs discovered by spider
        # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=368
        print 'Spider found %s additional URLs' % (len(zap.urls) - len(zap_urls))
        #TODO Wait for passive scanner to finish
        # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=367
        time.sleep(5)  # Give the passive scanner a chance to finish
    else:
        print 'Skipping spider'

    zap_alerts = copy.deepcopy(zap.alerts)

    # Active scan
    if session.config.option.zap_scan and session.config.option.zap_target:
        print '\rScan progress: 0%',
        zap.start_scan(session.config.option.zap_target)
        while int(zap.scan_status[0]) < 100:
            print '\rScan progress: %s%%' % zap.scan_status[0],
            sys.stdout.flush()
            time.sleep(1)
        print '\rScan progress: 100%'
        print 'Scan found %s additional alerts' % (len(zap.alerts) - len(zap_alerts))
        zap_alerts = copy.deepcopy(zap.alerts)
    else:
        print 'Skipping scan'

    # Save session
    #TODO Resolve 'Internal error' when saving
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=370
    if session.config.option.zap_save_session:
        print 'Saving session'

        if not session.config.option.zap_home:
            raise Exception('Home directory must be set using --zap-home command line option.')

        try:
            zap.save_session(os.path.join(os.path.abspath(session.config.option.zap_home), 'zap'))
        except:
            pass

        # Archive session
        #TODO Remove this
        # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=373
        zip = zipfile.ZipFile(os.path.join(session.config.option.zap_home, 'zap_session.zip'), 'w')
        session_files = glob.glob(os.path.join(session.config.option.zap_home, 'zap.session*'))
        if len(session_files) > 0:
            for file in session_files:
                zip.write(file, file.rpartition(os.path.sep)[2])
        else:
            raise Exception('No session files to archive.')
        zip.close()
    else:
        print 'Skipping save session'

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
            print '\nThe following alerts were ignored:'
            for alert in set([' * %s [%s]' % (i['alert'], i['risk']) for i in ignored_alerts]):
                print alert
    else:
        alerts.extend(zap_alerts)

    if alerts:
        print '\nThe following alerts were raised:'
        for alert in set([' * %s [%s]' % (i['alert'], i['risk']) for i in alerts]):
            print alert

    #TODO Save alerts report
    #TODO Save JUnit style report
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=371
    #TODO Save URLs report
    # Blocked by http://code.google.com/p/zaproxy/issues/detail?id=368

    if not session.config._zap_config.has_option('control', 'stop') or\
        session.config._zap_config.getboolean('control', 'stop'):
        print '\nStopping ZAP'
        session.config.zap_process.kill()
        #TODO Use API to shutdown ZAP, fallback to killing the process
#        zap.shutdown()
#        timeout = 60
#        end_time = time.time() + timeout
#        while(True):
#            try:
#                zap_url = 'http://%s:%s' % (session.config.option.zap_host,
#                                            session.config.option.zap_port)
#                proxies = {'http': zap_url,
#                           'https': zap_url}
#                urllib.urlopen('http://zap/', proxies=proxies)
#            except IOError:
#                break
#            time.sleep(1)
#            if(time.time() > end_time):
#                print 'Timeout after %s seconds waiting for ZAP to shutdown.' % timeout
#                session.config.zap_process.kill()


    #TODO Fail if alerts were raised (unless in observation mode)
