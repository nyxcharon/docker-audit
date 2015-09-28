#! /usr/bin/env ruby

require 'json'
require 'uri'
require 'net/http'
require 'ostruct'
require 'optparse'



class Audit
  @verbose = false
  #Vulernable OpenSSL versions
  @@openssl_versions = ['1.0.1a','1.0.1b','1.0.1c','1.0.1d','1.0.2-beta']

  def self.hound_url(url)
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    data = JSON.parse(response.body)

    images = []
    data['Results'].each do |line|
        line[1]['Matches'].each do |a|
             a['Matches'].each do |b|
                images += [b["Line"].strip.split(":")[1]]
              end
        end
    end
    return images
  end

  def self.list(list_string)
    if list_string.include?(',')
        images = list_string.split(',')
      elsif list_string
        images = [ list_string ]
      else
        images = ['']
      end
    return images
  end


  #Parse args
  def self.parse(args)
    options = OpenStruct.new
    options.verbose = false
    options.lynis = false
    options.hound = ""
    options.list = ""

    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: docker-audit.rb [options]"
      opts.on("-h", "--hound URL",
            "Hound URL to pull images from") do |url|
            options.hound << url
      end
      opts.on("-i", "--images URL",
            "Comma seperated list of images") do |list|
            options.list << list
      end
      opts.on("-v", "--verbose", "Run verbosely") do |v| options.verbose = v end
      opts.on("-l", "--lynis", "Run lynis scan") do |l| options.lynis = l end
    end
    opt_parser.parse!(args)
    options
  end

  def self.output(string)
    if @verbose
      puts string
    end
  end

  def self.test(options)
    if options.verbose
      @verbose = true
    end

    images = ""
    failed_test = ""
    if options.hound
      images = hound_url(options.hound)
    elsif options.list
      images = list(options.list)
    else
      puts "No images specified"
      exit 0
    end

    output("Checking the following images:\n #{images.uniq}")
    no_test = Array.new
    images.uniq.each do |image|
        output("--------------- Running #{image} -----------------")
        pull=%x[docker pull #{image} 2>&1]

        if pull.include?("Error: Status 403")
          output("Could not pull #{image}")
          no_test << "#{image}"
          next
        end

        bash=%x[docker run --rm --entrypoint=bash #{image} --version 2>&1]
        openssl=%x[docker run --rm --entrypoint=openssl #{image} version 2>&1]

        if  bash.include? "GNU"
          output ("Bash Version: "+bash.split("\n").first)
          shellshock=%x[docker run --rm -v /scripts:/scripts --entrypoint=/scripts/bashcheck #{image}]
          if shellshock.include?("FAILURE")
            failed_test += "#{image} - Failed shellshock test. "
            output("VULNERABLE: Bash is vulernable to shellshock")
          else
            output("OKAY: Bash is not vulerable to shellshock")
          end
        else
          output('Bash not found')
        end

        if openssl.include? "not found"
            output("Openssl not found")
        else
          output(openssl)
          if @@openssl_versions.include?(openssl)
            failed_test += "#{image} - Failed heartbleed test. "
            output("VULNERABLE: OpenSSL is vulernable to heartbleed")
          else
            output("OKAY: OpenSSL is not vulernable to heartbleed")
          end
        end

        if options.lynis
           lyn=%x[docker run --rm -v /lynis:/lynis --entrypoint=/lynis/lynis -w /lynis #{image} audit system --quick 2>&1]
           output(lyn)
        end

        rm=%x[docker rmi #{image} 2>&1]
    end #End image loop

    if failed_test.empty? and no_test.empty?
      puts "Audit Passed"
      exit 0
    elsif no_test.empty?
      puts "Audit Failed: "+failed_test
      exit 1
    else
      puts "Couldn't check these images: #{no_test.join(' ')}"
      exit 2
    end
  end
end

options = Audit.parse(ARGV)
Audit.test(options)
