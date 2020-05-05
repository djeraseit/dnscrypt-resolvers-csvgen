#!/usr/bin/env python

import base64
import csv
import itertools
import re
import sys

try:
    import requests
except ImportError:
    print("Please install `python-requests` before running this script")
    sys.exit(1)

DNSCRYPT_FIELDS = [
    "Name", "Full name", "Description", "Location", "Coordinates", "URL",
    "Version", "DNSSEC validation", "No logs", "Namecoin", "Resolver address",
    "Provider name", "Provider public key", "Provider public key TXT record"
]

if __name__ == "__main__":
    r = requests.get(
        "https://download.dnscrypt.info/dnscrypt-resolvers/json/public-resolvers.json"
    )
    r.raise_for_status()

    _csv = csv.DictWriter(
        open("dnscrypt-resolvers.csv", "w"), DNSCRYPT_FIELDS, dialect='unix'
    )
    _csv.writeheader()
    _csv.writerows(map(
        lambda i: {
            "Name": i.get("name"),
            "Full name": "",
            "Description": i.get("description", "").replace("\n", " "),
            "Location": i.get("country", ""),
            "Coordinates": "{lat:+.4f}, {long:+.4f}".format(**i.get("location", {})),
            "URL": "",
            "Version": 1 if i.get("proto") == "DNSCrypt" else 2,
            "DNSSEC validation": "yes" if i.get("dnssec") == True else "no",
            "No logs": "yes" if i.get("nolog") == True else "no",
            "Namecoin": "no",
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
                ''.join(map(
                    lambda j: "{:0>2X}".format(j),
                    base64.urlsafe_b64decode("{}==".format(
                        i.get("stamp", "").lstrip("sdns://")
                    )).split(b" ")[-1][:32]
                )),
                15
            ),
        },
        filter(  # personal filters go here
            lambda x: all([
                x.get("dnssec") == True,
                x.get("nolog") == True,
                x.get("nofilter") == True,
                x.get("proto") == "DNSCrypt",
                x.get("ipv6") == False,
            ]),
            r.json()
        )
    ))
