#!/usr/bin/env python

import argparse
import base64
import csv
import itertools
import json
import re
import sys

try:
    from urllib.request import urlopen
except ImportError:
    from urllib import urlopen


class unix_dialect(csv.Dialect):
    delimiter = ','
    quotechar = '"'
    doublequote = True
    skipinitialspace = False
    lineterminator = '\n'
    quoting = csv.QUOTE_ALL


def json_load(resp, encoding='utf-8'):
    if sys.version_info.major == 3 and sys.version_info.minor < 6:
        return json.loads(resp.read().decode(encoding))
    return json.load(resp)


DNSCRYPT_FIELDS = [
    "Name",
    # "Full name",
    "Description",
    "Location",
    "Coordinates",
    # "URL",
    "Version",
    "DNSSEC validation",
    "No logs",
    # "Namecoin",
    "Resolver address",
    "Provider name",
    "Provider public key",
    "Provider public key TXT record"
]


def generate_filter():
    parser = argparse.ArgumentParser(
        description="DNSCrypt (not DoH!) resolver list generator"
    )
    parser.add_argument(
        "--no-dnssec", action="store_false", default=True, dest="dnssec",
        help="allow resolvers not verifying DNS query response authenticity"
    )
    parser.add_argument(
        "--allow-logging", action="store_false", default=True, dest="nolog",
        help="allow resolvers not declaring they don't log queries"
    )
    parser.add_argument(
        "--allow-filter", action="store_false", default=True, dest="nofilter",
        help="allow resolvers not declaring they don't filter responses"
    )
    parser.add_argument(
        "--ipv6", action="store_true", default=False, dest="ipv6",
        help="allow resolvers available over IPv6"
    )
    options = parser.parse_args()

    return lambda i: all([
        i.get("dnssec") is True if options.dnssec else True,
        i.get("nolog") is True if options.nolog else True,
        i.get("nofilter") is True if options.nofilter else True,
        i.get("ipv6") is False if not options.ipv6 else True,
        i.get("proto") == "DNSCrypt",
    ])


if __name__ == "__main__":
    with open("dnscrypt-resolvers.csv", "w") as f:
        _csv = csv.DictWriter(f, DNSCRYPT_FIELDS, dialect=unix_dialect)
        _csv.writeheader()
        _csv.writerows(map(
            lambda i: {
                "Name": i.get("name"),
                # "Full name": "",
                "Description": i.get("description", "").replace("\n", " "),
                "Location": i.get("country", ""),
                "Coordinates": "{lat:+.4f}, {long:+.4f}".format(
                    **i.get("location", {})
                ),
                # "URL": "",
                "Version": 1 if i.get("proto") == "DNSCrypt" else 2,
                "DNSSEC validation": "yes" if i.get(
                    "dnssec"
                ) is True else "no",
                "No logs": "yes" if i.get("nolog") is True else "no",
                # "Namecoin": "no",
                "Resolver address": ",".join(map(
                    lambda y: ":".join(y),
                    itertools.product(
                        i.get("addrs", []),
                        map(str, i.get("ports", []))
                    )
                )),
                "Provider name": base64.urlsafe_b64decode(
                    # wtf, broken padding in stamp?
                    "{}==".format(i.get("stamp", "").lstrip("sdns://"))
                ).split(b" ")[-1][33:].decode("utf-8"),
                "Provider public key": re.sub(
                    r"(....)",
                    r"\1:",
                    "".join(map(
                        lambda j: "{:0>2X}".format(j),
                        base64.urlsafe_b64decode("{}==".format(
                            i.get("stamp", "").lstrip("sdns://")
                        )).split(b" ")[-1][:32]
                    )),
                    15
                ),
            },
            filter(
                generate_filter(),
                json_load(urlopen(
                    "https://download.dnscrypt.info/dnscrypt-resolvers/json/public-resolvers.json"  # noqa: E501
                ))
            )
        ))
