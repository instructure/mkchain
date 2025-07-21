# frozen_string_literal: true

require 'spec_helper'

RSpec.describe MkChain::Core do
  # Single valid cert for basic parsing tests
  let(:valid_pem) do
    key = OpenSSL::PKey::RSA.new(512)
    name = OpenSSL::X509::Name.parse('CN=Test')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = name
    cert.issuer = name
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert.to_pem
  end

  describe '.parse_pem' do
    it 'returns an array of certificates for valid PEM' do
      certs = described_class.parse_pem(valid_pem)
      expect(certs).to all(be_a(OpenSSL::X509::Certificate))
    end

    it 'raises UnknownFormat for garbage data' do
      expect { described_class.parse_pem('NOT A CERT') }
        .to raise_error(MkChain::UnknownFormat)
    end
  end

  describe '.parse_der' do
    let(:der_data) { OpenSSL::X509::Certificate.new(valid_pem).to_der }

    it 'returns array of cert for DER-encoded X.509' do
      certs = described_class.parse_der(der_data)
      expect(certs.first.subject.to_s).to include('CN=Test')
    end

    it 'raises UnknownFormat for invalid DER' do
      expect { described_class.parse_der('01020304') }
        .to raise_error(MkChain::UnknownFormat)
    end
  end
end
