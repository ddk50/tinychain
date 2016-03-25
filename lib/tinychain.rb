
require 'bundler/setup'
Bundler.require

require "tinychain/version"

module Tinychain
  # Your code goes here...
  MAGICK_HEADER = 0x11451419
  EVENT_INTERVAL = 10
  MAX_CONNECTIONS = 4
  NETWORKS = [
              {host: "127.0.0.1", port: 9991},
              {host: "127.0.0.1", port: 9992},
              {host: "127.0.0.1", port: 9993},
              {host: "127.0.0.1", port: 9994}
             ]
  POW_LIMIT = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff

  ## mining genesis hash 
  ## mining genesis hash time: 2016-03-21 20:19:52 +0900 (unixtime: 1458559192)
  ## genesis hash: 00000a268d97d5ed327cd8f2a76dbfd6791f2ff329e252527c3babcb1713f419, nonce: 646449
  GENESIS_HASH  = 0x00000a268d97d5ed327cd8f2a76dbfd6791f2ff329e252527c3babcb1713f419
  GENESIS_NONCE = 646449
  GENESIS_BITS  = 0x1903a30
  GENESIS_TIME  = 1458543219
  
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

  class Block
    attr_accessor :prev, :next
    attr_accessor :height, :bits, :nonce
    attr_accessor :time, :hash
    attr_accessor :blkblock
    attr_accessor :jsonstr

    attr_reader :genesis
    
    def initialize(genesis = false, prev_block, nonce, bits, time, height, jsonstr)
      @next = @prev = nil
      if genesis
        @prev    = prev_block
        @genesis = true
        @nonce   = GENESIS_NONCE
        @bits    = GENESIS_BITS
        @time     = GENESIS_TIME
        @height   = 0
        @jsonstr  = jsonstr
      else
        @genesis = false
        @nonce   = nonce
        @bits    = bits
        @time    = time.to_i
        @height  = height
        @jsonstr = jsonstr
      end
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

    def refresh
      @blkblock = @hash = nil
    end

    def to_json
      {type: "block", height: @height, prevhash: @prevhash.to_s(16).rjust(64, '0'), 
        nonce: @nonce, bit: @bits, time: @time.to_s, jsonstr: @jsonstr, 
        strlen: @jsonstr.size}.to_json
    end

    private
    def generate_blkblock
      prev_hash = @genesis ? 0x0 : @prev.to_sha256hash()
      @blkblock ||= Tinychain::BlkBlock.new(block_id: @height, time: @time, bits: @bits,
                                            prev_hash: prev_hash, strlen: @jsonstr.size(),
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
