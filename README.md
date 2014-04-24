pytest_zap
==========

pytest_zap is a plugin for [py.test](http://pytest.org/) that provides support for running [OWASP Zed Attack Proxy](http://owasp.com/index.php/OWASP_Zed_Attack_Proxy_Project).

Requires:

  * py.test
  * python-owasp-zap

Installation
------------

    $ python setup.py install

Usage
-----

For full usage details run the following command:

    $ py.test --help

    zap:
      --zap-interactive   run zap in interactive mode. (default: False)
      --zap-path=path     location of zap installation.
      --zap-log=path      location of zap log file (default zap.log)
      --zap-home=path     location of zap home directory.
      --zap-config=path   location of zap configuration file. (default: zap.cfg)
      --zap-host=str      host zap is listening on. (default: localhost)
      --zap-port=int      port zap is listening on. (default: 8080)
      --zap-target=url    target url for spider and scan.
      --zap-exclude=str   exclude urls matching this regex when scanning.
      --zap-spider        spider the target. (default: False)
      --zap-scan          scan the target. (default: False)
      --zap-save          save the zap session in zap.session within home directory. (default: False)
      --zap-load=path     location of an archived zap session to open.
      --zap-ignore=path   location of ignored alerts text file. (default: zap_ignore.txt)
      --zap-skip-tests    skip all tests
      --zap-observe       enable observation mode to prevent failing when alerts are found. (default False)
