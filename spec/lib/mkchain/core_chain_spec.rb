# frozen_string_literal: true

require 'spec_helper'

RSpec.describe MkChain::Core do
  let(:root_key)         { OpenSSL::PKey::RSA.new(2048) }
  let(:intermediate_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:leaf_key)         { OpenSSL::PKey::RSA.new(2048) }

  let(:root_name)         { OpenSSL::X509::Name.parse('CN=Test Root CA') }
  let(:intermediate_name) { OpenSSL::X509::Name.parse('CN=Test Intermediate CA') }
  let(:leaf_name)         { OpenSSL::X509::Name.parse('CN=example.com') }

  let(:root_cert) do
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = 1
    cert.subject    = root_name
    cert.issuer     = root_name
    cert.public_key = root_key.public_key
    cert.not_before = Time.now
    cert.not_after  = cert.not_before + 3600
    cert.add_extension \
      OpenSSL::X509::Extension.new('basicConstraints', 'CA:TRUE', true)
    cert.add_extension \
      OpenSSL::X509::Extension.new('keyUsage', 'keyCertSign, cRLSign', true)

    cert.sign(root_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  let(:intermediate_cert) do
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = 2
    cert.subject    = intermediate_name
    cert.issuer     = root_cert.subject
    cert.public_key = intermediate_key.public_key
    cert.not_before = Time.now
    cert.not_after  = cert.not_before + 3600
    cert.add_extension \
      OpenSSL::X509::Extension.new('basicConstraints', 'CA:TRUE, pathlen:0', true)
    cert.add_extension \
      OpenSSL::X509::Extension.new('keyUsage',
                                   'digitalSignature, keyCertSign, cRLSign', true)

    cert.sign(root_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  let(:leaf_cert) do
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = 3
    cert.subject    = leaf_name
    cert.issuer     = intermediate_cert.subject
    cert.public_key = leaf_key.public_key
    cert.not_before = Time.now
    cert.not_after  = cert.not_before + 3600
    cert.add_extension \
      OpenSSL::X509::Extension.new('authorityInfoAccess',
                                   'CA Issuers - URI:http://example.com/intermediate.der')

    cert.sign intermediate_key, OpenSSL::Digest.new('SHA256')
    cert
  end

  let(:self_cert) do
    key = OpenSSL::PKey::RSA.new(512)
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = 4
    cert.subject    = leaf_name
    cert.issuer     = leaf_name
    cert.public_key = leaf_key.public_key
    cert.not_before = Time.now
    cert.not_after  = cert.not_before + 3600
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  let(:fake_ctx) do
    instance_double(
      OpenSSL::X509::StoreContext,
      verify: true,
      error_string: nil,
      chain: [leaf_cert, intermediate_cert, root_cert]
    )
  end

  let(:mkchain_default) { described_class.new }
  let(:mkchain_fullchain) do
    described_class.new(
      include_leaf: true,
      include_root: true,
      cacert_date: nil
    )
  end

  before do
    # stub the network fetch for our mkchain instances so .chain will enqueue our intermediate
    [mkchain_default, mkchain_fullchain].each do |mkchain|
      allow(mkchain).to receive(:fetch_certificates)
        .with('http://example.com/intermediate.der')
        .and_return([intermediate_cert])
    end

    # intercept the CA-bundle download to avoid network calls
    allow(URI).to receive(:parse).and_wrap_original do |orig, url|
      if url =~ %r{^https://curl\.se/ca/cacert(-\d{4}-\d{2}-\d{2})?\.pem$}
        instance_double(OpenURI::OpenRead, read: root_cert.to_pem)
      else
        orig.call(url)
      end
    end

    # stub StoreContext to always verify and yield our fake chain
    allow(OpenSSL::X509::StoreContext).to receive(:new)
      .and_return(fake_ctx)
  end

  describe '.chain input' do
    it 'errors when input is nil' do
      expect { mkchain_default.chain(nil) }
        .to raise_error(ArgumentError, /cannot be nil or empty/)
    end

    it 'errors when input is empty' do
      expect { mkchain_default.chain('   ') }
        .to raise_error(ArgumentError, /cannot be nil or empty/)
    end

    it 'errors when no intermediates found' do
      expect { mkchain_default.chain(self_cert.to_pem) }
        .to raise_error(MkChain::NoChainFoundException, /No intermediate/)
    end
  end

  describe '.chain output' do
    context 'with default flags' do
      subject(:pem) { mkchain_default.chain(leaf_cert.to_pem) }

      it 'includes only the intermediate certificate' do
        expect(pem).to include intermediate_cert.to_pem
      end

      it 'does not include the root certificate' do
        expect(pem).not_to include root_cert.to_pem
      end
    end

    context 'when include_leaf and include_root are true' do
      subject(:pem) do
        mkchain_fullchain.chain(leaf_cert.to_pem)
      end

      it 'starts with the leaf certificate' do
        expect(pem).to start_with(leaf_cert.to_pem)
      end

      it 'ends with the root certificate' do
        expect(pem).to end_with(root_cert.to_pem)
      end
    end
  end
end
