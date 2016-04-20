
require 'bundler/setup'
Bundler.require

require "tinychain/version"

module Tinychain

  class InvalidUnknownFormat < StandardError; end
  class InvalidFieldFormat < StandardError; end
  class InvalidRequest < StandardError; end
  class InvalidBlock < StandardError; end
  class NoAvailableBlockFound < StandardError; end
  
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
  POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60 ## two weeks
  POW_DIFFICULTY_BLOCKSPAN = 2016

  ## target: 0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  ## mining genesis hash time: 2016-04-19 09:19:36 +0900 (unixtime: 1461025176)
  ## genesis hash: 0000610c19db37b3352ef55d87bc22426c8fa0a7333e08658b4a7a9b95bc54cf, nonce: 8826
  GENESIS_HASH  = "0000610c19db37b3352ef55d87bc22426c8fa0a7333e08658b4a7a9b95bc54cf"
  GENESIS_NONCE = 8826
  GENESIS_BITS  = 0x1effffff
  GENESIS_TIME  = 1461025176 

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

    attr_reader :root
    attr_accessor :winner_block_head

    def initialize(genesis_block)
      @root = genesis_block
    end

    def add_block(prev_hash, newblock)
      block = find_block_by_hash(prev_hash)
      
      raise NoAvailableBlockFound if block == nil
      block.next << newblock
      
      winner_block = find_winner_block_head(true)
      
      if newblock.to_sha256hash_s == winner_block.to_sha256hash_s
        @winner_block_head = newblock
      end

      return newblock
    end

    def find_winner_block_head(refresh = false)
      if refresh
        @winner_block_head = nil
      end
      @winner_block_head ||= do_find_winner_block_head(@root, 0, 0, GENESIS_BITS).first
    end
    
    def do_find_winner_block_head(block, depth, cumulative_depth, difficulty)
      
      return [block, depth, cumulative_depth] if block.next.size == 0

      depth += 1

      if cumulative_depth > POW_DIFFICULTY_BLOCKSPAN
        cumulative_depth = 0        
        difficulty = block_new_difficulty(difficulty, block.time)
      else
        cumulative_depth += 1
      end
      
      if block.next.size > 1
        ## has branch 
        current_depth = 0
        current_cdp = cumulative_depth
        deepest_block = block.next.first

        ## find a winner block
        block.next.each{|b|
          bl, dp, cdp = do_find_winner_block_head(b, 1, 1, difficulty)
          if dp > current_depth then
            current_depth = dp
            current_cdp   = cdp
            deepest_block = bl
          end
        }

        return [deepest_block, depth + current_depth,
                cumulative_depth + current_cdp, difficulty]
      else       
        
        ## has no branch
        return do_find_winner_block_head(block.next.first, depth, cumulative_depth, difficulty)
      end
    end
    
    def find_block_by_hash(hash_str)
      do_find_block_by_hash(@root, hash_str)
    end

    def do_find_block_by_hash(block, hash_str)

      return block if block.to_sha256hash_s == hash_str
      return nil if block.next.size == 0

      block.next.each{|b|
        tmp = do_find_block_by_hash(b, hash_str)
        if tmp != nil
          ##
          ## found it
          ##
          return tmp
        end
      }

      return nil
    end

    ##
    ## time_of_lastblocks: uint64_t
    ##
    def self.block_new_difficulty(old_difficulty, time_of_lastblocks)
      new_difficulty = old_difficulty * (time_of_lastblocks / 20160.0)
      return new_difficulty.to_i
    end

    def self.get_target(bits)
      coefficient = bits & 0xffffff
      exponent    = (bits >> 24) & 0xff

      target     = coefficient * (2 ** (8 * (exponent - 3)))
      str        = target.to_s(16).rjust(64, '0')
      target_str = ""

      str.reverse!
      
      first_hex = nil
      str.each_char{|c|        
        if first_hex == nil && c != '0'
          first_hex = true
        end

        if first_hex && c == '0'
          break
        end
        
        target_str << 'f'
      }

      return [target_str.rjust(64, '0'), target]
    end

    def self.do_mining(log, bits, payloadstr)
      target = BlockChain.get_target(bits).first
      
      found = nil
      nonce = 0
      t = target.to_i(16)
      
      time = Time.now
      log.info { "time of start mining: #{time} (unixtime: #{time.to_i})" }
      inttime = time.to_i
      
      until found               
        d = Tinychain::BlkBlock.new(nonce: nonce, block_id: 0,
                                    time: inttime, bits: bits,
                                    prev_hash: 0, strlen: 0, payloadstr: "")
        h = Digest::SHA256.hexdigest(Digest::SHA256.digest(d.to_binary_s)).to_i(16)

        if h <= t
          found = [h.to_s(16).rjust(64, '0'), nonce]
          break
        end
        nonce += 1
      end
      log.info { "found! hash: #{found[0]}, nonce: #{found[1]}" }
      
      return nonce
    end

    def self.do_local_mining_connecting_chains(log)
      
      genesis = Tinychain::Block.new_genesis()
      
      loop do
      ##  Tinychain::Block.do_mining(log, )
      end
    end

  end

  class Block
    attr_accessor :prev_hash
    attr_accessor :height, :bits, :nonce
    attr_accessor :time, :hash
    attr_accessor :blkblock
    attr_accessor :jsonstr
    attr_accessor :genesis
    
    attr_accessor :next, :prev

    def self.new_genesis()
      obj = self.new
      obj.genesis   = true
      obj.nonce     = GENESIS_NONCE
      obj.bits      = GENESIS_BITS
      obj.time      = GENESIS_TIME
      obj.prev_hash = 0
      obj.height    = 0
      obj.jsonstr   = ""
      obj.prev      = []
      obj.next      = []
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
      obj.prev    = []
      obj.next    = []
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
        obj.prev      = []
        obj.next      = []
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
      
      target = BlockChain.get_target(GENESIS_BITS).first
      
      puts "target: " + target
      
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

        nonce += 1
        
      end
      puts "genesis hash: #{found[0]}, nonce: #{found[1]}"
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

