# frozen_string_literal: true

require 'openssl'
require 'open-uri'

module MkChain
  class NoChainFoundException < StandardError; end
  class UnknownFormat < StandardError; end

  class Core
    def self.parse_pem(data)
      # First try to parse as PEM-encoded X.509 certificates
      begin
        pem_blocks = data.scan(/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/m).flatten
        certs = pem_blocks.map do |block|
          OpenSSL::X509::Certificate.new([
            '-----BEGIN CERTIFICATE-----',
            block.strip,
            '-----END CERTIFICATE-----'
          ].join("\n"))
        end

        return certs unless certs.empty?
      rescue OpenSSL::X509::CertificateError
        # fall through to try PKCS#7
      end

      # Otherwise attempt PEM-encoded PKCS#7
      begin
        pkcs7 = OpenSSL::PKCS7.new(data)
        return pkcs7.certificates if pkcs7.certificates.any?
      rescue OpenSSL::PKCS7::PKCS7Error, ArgumentError
        # fall through
      end

      raise UnknownFormat, 'Invalid PEM/PKCS#7 format'
    end

    def self.parse_der(data)
      # Try to parse as PKCS#7 format first since it can wrap X.509 certs
      begin
        pkcs7 = OpenSSL::PKCS7.new(data)
        return pkcs7.certificates if pkcs7.certificates.any?
      rescue OpenSSL::PKCS7::PKCS7Error, ArgumentError
        # fall through to try X.509 parsing
      end

      # If it fails, try to parse as a single X.509 certificate
      begin
        cert = OpenSSL::X509::Certificate.new(data)
        return [cert]
      rescue OpenSSL::X509::CertificateError
        # fall through
      end

      raise UnknownFormat, 'Invalid DER format - could not parse as PKCS#7 or X.509'
    end

    def initialize(options = {})
      @options = { include_leaf: false, include_root: false, cacert_date: nil }.merge(options)
    end

    def fetch_certificates(url)
      @certificate_cache ||= {}
      return @certificate_cache[url] if @certificate_cache.key?(url)

      result = begin
        data = URI.parse(url).read
        if data.start_with?('-----BEGIN ')
          self.class.parse_pem(data)
        elsif data.getbyte(0) == 0x30
          self.class.parse_der(data)
        else
          raise UnknownFormat, "Unknown certificate format - found leading bytes: #{data.byteslice(0, 4).unpack('H*')}"
        end
      rescue OpenURI::HTTPError => e
        raise "Failed to fetch certificates from #{url}: #{e.message}"
      end

      @certificate_cache[url] = result
      result
    end

    def chain(cert_str) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
      # Ensure we have a valid certificate string
      raise ArgumentError, 'Certificate string cannot be nil or empty' if cert_str.nil? || cert_str.strip.empty?

      # If cacert_date is provided, attempt to load a CA bundle at the specified revision
      cacert_date = @options.fetch(:cacert_date, nil)
      cacert_url = "https://curl.se/ca/cacert#{"-#{cacert_date}" if cacert_date}.pem"
      begin
        # Download the CA bundle from the specified date to a temporary file
        require 'tempfile'
        tempfile = Tempfile.new("cacert-#{cacert_date || 'latest'}.pem")
        tempfile.binmode
        tempfile.write(URI.parse(cacert_url).read)
        tempfile.rewind

        # Load the CA bundle into an OpenSSL::X509::Store
        ca_store = OpenSSL::X509::Store.new
        ca_store.add_file(tempfile.path)
        tempfile.close
        tempfile.unlink
      rescue OpenSSL::X509::StoreError => e
        raise "Failed to load CA bundle (#{cacert_date || 'latest'}): #{e.message}"
      end

      # Parse the certificate and initialize the chain
      leaf = OpenSSL::X509::Certificate.new(cert_str)
      untrusted = []

      # Walk through the certificate chain to find intermediates based on AIA extensions
      queue = [leaf]
      while (current = queue.shift)
        # rubocop:disable Style/SafeNavigationChainLength
        uri = current.extensions.find { |ext| ext.oid == 'authorityInfoAccess' }
                     &.value
                     &.scan(%r{CA Issuers - URI:(https?://\S+)})
                     &.flatten&.first
        # rubocop:enable Style/SafeNavigationChainLength
        next unless uri

        fetch_certificates(uri).each do |c|
          next if c.subject == c.issuer # Skip self-signed/root certs

          key = [c.subject.to_s, c.issuer.to_s, c.serial]
          unless untrusted.any? { |u| key == [u.subject.to_s, u.issuer.to_s, u.serial] }
            untrusted << c
            queue << c
          end
        end
      end
      raise NoChainFoundException, 'No intermediate certificates found' if untrusted.empty?

      # Attempt to build the chain from the untrusted certificates using the CA store
      ctx = OpenSSL::X509::StoreContext.new(ca_store, leaf, untrusted)
      raise "Failed to verify and build chain: #{ctx.error_string}" unless ctx.verify

      # Collect the chain from the context
      chain = ctx.chain
      raise NoChainFoundException, 'No valid certificate chain found' if chain.empty?

      # Remove the root and/or leaf if not requested
      chain = chain[..-2] if @options[:include_root] == false
      chain = chain[1..] if @options[:include_leaf] == false

      # Return the chain as an array of PEM-encoded strings
      chain.join
    end
  end
end
