from xml.dom.minidom import parse
from ConfigParser import SafeConfigParser
from urlparse import urlparse
import copy
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
        help='run zap in interactive mode. (default: %default)'),
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
    group._addoption('--zap-url',
        action='store',
        dest='zap_url',
        metavar='url',
        help='address zap is listening on. (default: http://localhost:8080)')
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

    config.option.zap_url = config.option.zap_url or\
                            (hasattr(config.option, 'proxy_url') and config.option.proxy_url) or\
                            'http://localhost:8080'
    config.option.zap_target = config.option.zap_target or\
                               (hasattr(config.option, 'base_url') and config.option.base_url)


def pytest_sessionstart(session):
    if hasattr(session.config, 'slaveinput') or session.config.option.collectonly:
        return

    if not session.config._zap_config.has_option('control', 'start') or\
       session.config._zap_config.getboolean('control', 'start'):
        #TODO Test on additional platforms
        if platform.system() == 'Windows':
            zap_script = ['start /b zap.bat']
        elif platform.system() == 'Darwin':
            zap_script = ['java', '-jar', 'zap.jar']
        else:
            zap_script = ['zap.sh']

        if not session.config.option.zap_interactive:
            # Run as a daemon
            zap_script.append('-daemon')

        zap_path = session.config.option.zap_path
        if not zap_path:
            if platform.system() == 'Windows':
                # Win 7 default path
                zap_path = 'C:\Program Files (x86)\OWASP\Zed Attack Proxy'
                if not os.path.exists(zap_path):
                    # Win XP default path
                    zap_path = "C:\Program Files\OWASP\Zed Attack Proxy"
            elif platform.system() == 'Darwin':
                zap_path = '/Applications/OWASP ZAP.app/Contents/Resources/Java'
            else:
                # No default path for Linux
                print 'Installation directory must be set using --zap-path command line option.'

        zap_home = session.config.option.zap_home and\
                   os.path.abspath(session.config.option.zap_home) or\
                   os.sep.join([zap_path, 'home'])

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

        # Set proxy
        proxy = config.getElementsByTagName('proxy')[0]
        ip = proxy.getElementsByTagName('ip')[0]
        ip.replaceChild(
            document.createTextNode(urlparse(session.config.option.zap_url).hostname),
            ip.firstChild)
        port = proxy.getElementsByTagName('port')[0]
        port.replaceChild(
            document.createTextNode(str(urlparse(session.config.option.zap_url).port)),
            port.firstChild)

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
        subprocess.Popen(zap_script, cwd=zap_path, stdout=subprocess.PIPE)
        #TODO Wait for the proxy to be running, fail if it's not after reasonable timeout
        #TODO If launching, check that ZAP is not currently running?
        #TODO Support opening a saved session
        while True:
            try:
                proxies = {'http': session.config.option.zap_url,
                           'https': session.config.option.zap_url}
                status = urllib.urlopen('http://zap/', proxies=proxies).getcode()
                if status == 200:
                    break
            except IOError:
                pass
            time.sleep(1)


def pytest_sessionfinish(session):
    if hasattr(session.config, 'slaveinput') or session.config.option.collectonly:
        return

    print '\n'
    zap_url = session.config.option.zap_url
    zap = ZAP(proxies={'http': zap_url, 'https': zap_url})
    #TODO Wait for passive scanner to finish
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
        print 'Spider found %s additional URLs' % (len(zap.urls) - len(zap_urls))
        #TODO Wait for passive scanner to finish
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
    print 'Saving session'
    try:
        zap.save_session('zap')
        #TODO Wait for save to finish
        time.sleep(10)  # Saving is asynchronous
    except:
        pass

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
    #TODO Save URLs report

    if not session.config._zap_config.has_option('control', 'stop') or\
        session.config._zap_config.getboolean('control', 'stop'):
        print '\nStopping ZAP'
        zap.shutdown()

    #TODO Fail if alerts were raised (unless in observation mode)
