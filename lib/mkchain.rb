require 'openssl'
require 'open-uri'

class MkChain
  class NoChainFoundException < Exception; end

  def self.chain(cert_str)
    chain = []
    cert = OpenSSL::X509::Certificate.new(cert_str)

    loop do
      url = cert.extensions.select { |ext| ext.oid == 'authorityInfoAccess' }
        .first.value.match(%r{^CA Issuers - URI:(https?://.+)$})[1] rescue break

      cert = OpenSSL::X509::Certificate.new(open(url).read) rescue break
      chain << cert.to_pem
    end

    raise NoChainFoundException, 'No intermediate chain found' if chain.empty?

    # the last cert will be the root cert, which doesn't belong in the chain
    chain[0..-1].join
  end
end
