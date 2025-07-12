# frozen_string_literal: true

require 'optparse'

module MkChain
  class CLI
    def self.start(argv = ARGV)
      new.run(argv)
    end

    def run(argv)
      options = parse_options(argv)

      filename = argv.shift&.strip
      abort 'No certificate file specified.' if filename.nil? || filename.empty?
      abort "No such file '#{filename}'" unless File.exist?(filename)
      abort "Cannot read file '#{filename}'" unless File.readable?(filename)

      puts MkChain::Core.new(options).chain(File.read(filename))
    rescue ArgumentError, MkChain::NoChainFoundException, MkChain::UnknownFormat => e
      puts "Error: #{e.message}"
      exit 1
    rescue StandardError => e
      puts "Unexpected error: #{e.message}"
      exit 1
    end

    private

    def parse_options(argv) # rubocop:disable Metrics/MethodLength
      options = {
        include_leaf: false,
        include_root: false,
        cacert_date: nil
      }
      opt_parser = OptionParser.new do |opts|
        opts.banner = 'Usage: mkchain [options] <cert-filename>'
        opts.on('-h', '--help', 'Display this help message') do
          puts opts
          exit
        end
        opts.on('-l', '--include-leaf', 'Include the leaf certificate') do
          options[:include_leaf] = true
        end
        opts.on('-r', '--include-root', 'Include the root certificate') do
          options[:include_root] = true
        end
        opts.on('-c', '--cacert-date DATE',
                'Build chain against a specific CA bundle revision for better legacy client ' \
                'compatibility. See https://curl.se/docs/caextract.html') do |date|
          options[:cacert_date] = Date.parse(date)
          require 'net/http'
          require 'uri'
          uri = URI("https://curl.se/ca/cacert-#{date}.pem")
          response = Net::HTTP.get_response(uri)
          if response.code.to_i != 200
            raise "No CA bundle found for date #{date}. Please check the date format or availability. " \
                  'For a subset of available revisions, visit https://curl.se/docs/caextract.html'
          end

          options[:cacert_date] = date
        rescue Date::Error
          puts 'Invalid date format. Use YYYY-MM-DD.'
          exit 1
        rescue StandardError => e
          puts "Error fetching CA bundle: #{e.message}"
          exit 1
        end
        opts.on('-v', '--version', 'Display version information') do
          puts "mkchain #{MkChain::VERSION}"
          exit
        end
      end

      opt_parser.parse!(argv)
      options
    end
  end
end
