# DNSCrypt (not DoH!) resolver list generator

## Summary

With the dawn of DNS-over-HTTPS effectively hijacking the now-effectively-legacy DNSCrypt implementation, there's a class of devices which may never see a DoH-based implementation.

This (rather clunky and poorly written) Python3 script scrapes the list of public resolvers (using [python-requests](https://github.com/psf/requests)) and extracts a [legacy DNSCrypt-Proxy](https://github.com/dyne/dnscrypt-proxy) consumable CSV list of those still running the legacy protocol, with some personal preferences of mine.
