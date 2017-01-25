# mkchain

Given a certificate filename as input, `mkchain` will attempt to build the
intermediate certificate chain, and print it to stdout. This replaces the
need to copy/edit cert-vendor provided chain files and deal with certificate
order.


## Installation

    $ rake gem:install


## Command-line Usage

    $ mkchain site.example.com.crt > site.example.com.chain


## Ruby Library

You can also invoke `mkchain` from Ruby code:

    require 'mkchain'
    chain_str = MkChain.chain(File.read(cert_filename))

This method returns a string containing the contents of the intermediate
chain in PEM format. If no chain can be built from the certificate, a
`MkChain::NoChainFoundException` will be raised. If no chain is necessary
(ie, if the certificate was signed directly by the root CA), then an empty
string will be returned.


## No guarantee

This method of building an intermediate chain depends on the signing
certificate being in the `authorityInfoAccess` X.509 extension field under
`CA Issuers`. That's a common but not universal pattern.


## Similar Tools

* https://whatsmychaincert.com/
* https://github.com/SSLMate/mkcertchain
