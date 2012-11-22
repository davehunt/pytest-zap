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
      --zap-home=path     location of zap home directory.
      --zap-config=path   location of zap configuration file. (default: zap.cfg)
      --zap-host=str      host zap is listening on. (default: localhost)
      --zap-port=int      port zap is listening on. (default: 8080)
      --zap-target=url    target url for spider and scan.
      --zap-spider        spider the target. (default: False)
      --zap-scan          scan the target. (default: False)
      --zap-save-session  save the zap session in zap.session within home directory. (default: False)
      --zap-ignore=path   location of ignored alerts text file. (default: zap_ignore.txt)
      --zap-cert=path     location of ssl certificate. (default: zap.cert)
