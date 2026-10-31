# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
from lxml import etree


def resolving_parser(data):
    # ruleid: auditor.python.xxe.lxml-unsafe-parser
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)


def network_parser(data):
    # ruleid: auditor.python.xxe.lxml-unsafe-parser
    parser = etree.XMLParser(no_network=False)
    return etree.fromstring(data, parser)


def hardened_parser(data):
    # ok: auditor.python.xxe.lxml-unsafe-parser
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(data, parser)


def boundary_default_parser(data):
    # Known false negative: lxml's default parser behaviour depends on the lxml version
    # (resolve_entities default changed in lxml 5); only explicit unsafe options are reported.
    # todoruleid: auditor.python.xxe.lxml-unsafe-parser
    return etree.fromstring(data)
