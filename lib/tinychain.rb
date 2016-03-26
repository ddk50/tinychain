
require 'bundler/setup'
Bundler.require

require "tinychain/version"

module Tinychain

  class InvalidUnknownFormat < StandardError; end
  class InvalidFieldFormat < StandardError; end
  class InvalidRequest < StandardError; end
  
  
  MAGICK_HEADER = 0x11451419
  EVENT_INTERVAL = 10
  MAX_CONNECTIONS = 4
  NETWORKS = [
              {host: "127.0.0.1", port: 9991},
              {host: "127.0.0.1", port: 9992},
              {host: "127.0.0.1", port: 9993},
              {host: "127.0.0.1", port: 9994}
             ]
  POW_LIMIT = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  
  # mining genesis hash time: 2016-03-25 19:42:55 +0900 (unixtime: 1458902575)
  # genesis hash: 000008bc651142e421e4c4f9b83883d149b2b0871155c63edf84b9083f0fdcc1, nonce: 1264943
  GENESIS_HASH  = "000008bc651142e421e4c4f9b83883d149b2b0871155c63edf84b9083f0fdcc1"
  GENESIS_NONCE = 1264943
  GENESIS_BITS  = 0x1903a30
  GENESIS_TIME  = 1458902575
  
  POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60 ## two weeks

  class BlkBlock < BinData::Record
    endian :little
    uint64 :block_id
    uint64 :time
    uint64 :bits
    bit256 :prev_hash
    uint32 :strlen
    string :payloadstr, :read_length => :strlen
    uint64 :nonce
  end

  class Packet < BinData::Record
    endian :little
    uint32 :magicknumber
    uint32 :command
    uint32 :strlen
    string :payloadstr, :read_length => :strlen
  end

  class BlockChain
    attr_accessor :next, :prev

    def initialize(block)
    end

    def add_block
    end
    
  end

  class Block
    attr_accessor :prev_hash
    attr_accessor :height, :bits, :nonce
    attr_accessor :time, :hash
    attr_accessor :blkblock
    attr_accessor :jsonstr
    attr_accessor :genesis

    def self.new_genesis()
      obj = self.new
      obj.genesis   = true
      obj.nonce     = GENESIS_NONCE
      obj.bits      = GENESIS_BITS
      obj.time      = GENESIS_TIME
      obj.prev_hash = 0
      obj.height    = 0
      obj.jsonstr   = ""
      return obj
    end

    def self.new_block(prev_hash, nonce, bits, time, height, payloadstr)
      obj = self.new
      obj.prev_hash  = prev_hash
      obj.genesis = false
      obj.nonce   = nonce
      obj.bits    = bits
      obj.time    = time.to_i
      obj.height  = height
      obj.jsonstr = payloadstr
      return obj
    end

    def self.parse_json(jsonstr)
      jsonhash = JSON.parse(jsonstr)
      raise InvalidUnknownFormat if not jsonhash["type"] == "block"
      obj = self.new
      begin
        obj.height    = jsonhash["height"]
        obj.prev_hash = jsonhash["prev_hash"].to_i(16)
        obj.nonce     = jsonhash["nonce"]
        obj.bits      = jsonhash["bits"]
        obj.time      = jsonhash["time"]
        obj.jsonstr   = jsonhash["jsonstr"]
      rescue KeyError => e
        raise InvalidFieldFormat
      end
      return obj
    end

    def to_binary_s
      blkblock = generate_blkblock()
      return blkblock.to_binary_s
    end

    def to_sha256hash
      blkblock = generate_blkblock()
      @hash ||= Digest::SHA256.hexdigest(Digest::SHA256.digest(blkblock.to_binary_s)).to_i(16)
      return @hash
    end

    def to_sha256hash_s
      to_sha256hash.to_s(16).rjust(64, '0')
    end

    def refresh
      @blkblock = @hash = nil
    end

    def to_json
      {type: "block", height: @height, prev_hash: @prev_hash.to_s(16).rjust(64, '0'), 
        nonce: @nonce, bit: @bits, time: @time, jsonstr: @jsonstr}.to_json
    end

    private
    
    def generate_blkblock
      @blkblock ||= Tinychain::BlkBlock.new(block_id: @height, time: @time, bits: @bits,
                                            prev_hash: @prev_hash, strlen: @jsonstr.size(),
                                            payloadstr: @jsonstr, nonce: @nonce)
      return @blkblock
    end

    public
    
    def self.generate_genesis_block
      target = "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      
      found = nil
      nonce = 0
      t = target.to_i(16)
      
      time = Time.now
      puts "mining genesis hash time: #{time} (unixtime: #{time.to_i})"
      inttime = time.to_i
      
      until found
        
        $stdout.print sprintf("trying... %d \r", nonce)
        
        d = Tinychain::BlkBlock.new(nonce: nonce, block_id: 0,
                                    time: inttime, bits: GENESIS_BITS,
                                    prev_hash: 0, strlen: 0, payloadstr: "")
        h = Digest::SHA256.hexdigest(Digest::SHA256.digest(d.to_binary_s)).to_i(16)

        if h <= t
          found = [h.to_s(16).rjust(64, '0'), nonce]
          break
        end

        nonce+=1       
        
      end
      puts "genesis hash: #{found[0]}, nonce: #{found[1]}"
    end

    ##
    ## time_of_lastblocks: uint64_t
    ##
    def self.block_new_difficulty(old_difficulty, time_of_lastblocks)
      new_difficulty = old_difficulty * (time_of_lastblocks / 20160.0)
      return new_difficulty.to_i
    end
    
  end

  class Node

    attr_accessor :sockaddr
    attr_accessor :connections
    attr_accessor :timers
    attr_accessor :log
    attr_accessor :timers

    def initialize(host, port, connections, log)
      @sockaddr = [host, port]
      @connections = connections
      @timers = {}
      @log = log
      @current_block_height = 0

      build_genesis_block()
    end

    def run
      EM.run do

        start_timer()

        host = @sockaddr[0]
        port = @sockaddr[1]
        EM.start_server(host, port, Tinychain::ConnectionHandler, host, port, @connections, @log)
      end
    end

    def start_timer
      [:ping, :getblock, :inv_block].each do |func|
        timers[func] = EM.add_periodic_timer(EVENT_INTERVAL, method("work_#{func}"))
      end      
    end
    
    def work_ping
      @log.info { "<< ping" }
      @connections.each{|conn|
        conn.send_ping()
      }      
    end

    def work_getblock      
      @log.info { "<< getblock" }
    end

    def work_inv_block
    end

    def work_connect
      if MAX_CONNECTIONS > @connections.size
      else
      end
    end
    
  end

  class ConnectionHandler < EM::Connection   

    attr_accessor :sockaddr
    attr_accessor :connections
    attr_accessor :log
    
    def initialize(host, port, connections, log)
      @sockaddr = [host, port]
      @connections = connections
      @log = log
    end

    def on_handshake_begin
      str = "hello"
      pkt = Packet.new(magicknumber: MAGICK_HEADER,
                       strlen: str.size,
                       payloadstr: str)
      send_data(pkt.to_binary_s)
      @connections << self
    end

    def on_ping
    end

    def on_receive_block
      
    end

    def post_init
      EM.schedule{ on_handshake_begin }      
    end
    
    def receive_data(data)
      parse_data(data)
    end

    def send_ping()
      str = "ping"
      pkt = Packet.new(magicknumber: MAGICK_HEADER,
                       command: 117,
                       strlen: str.size,
                       payloadstr: str)
      send_data(pkt.to_binary_s)
    end

    def parse_data(data)
      pkt = Packet.read(data)
      p pkt.magicknumber
      p pkt.strlen
      p pkt.payloadstr
    end

    def unbind
      @log.info {"disconnected #{@sockaddr} "}
      @connections.delete(self)
    end

    def self.connect_peer(host, port, connections, log)
      desired = connections.size
      if desired < MAX_CONNECTIONS        
        log.info { "connecting peer #{host}:#{port} ... " }
        EM.connect(host, port, Tinychain::ConnectionHandler, 
                   host, port, connections, log)
      else
        log.info { "max connections has been reached" }
      end
    end
    
  end
end

