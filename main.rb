#!/usr/bin/env ruby

require 'bundler/setup'
Bundler.require

module TinyChain

  MAGICK_HEADER = 0x11451419
  EVENT_INTERVAL = 10
  MAX_CONNECTIONS = 4
  NETWORKS = [
              {host: "127.0.0.1", port: 9991},
              {host: "127.0.0.1", port: 9992},
              {host: "127.0.0.1", port: 9993},
              {host: "127.0.0.1", port: 9994}
             ]

  class Transaction < BinData::Record
  end

  class Block < BinData::Record
    endian :little
    bit256 :prev_hash
    uint32 :test_value
  end

  class Packet < BinData::Record
    endian :little
    uint32 :command
    uint32 :magicknumber
    uint32 :strlen
    string :payloadstr, :read_length => :strlen
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
        EM.start_server(host, port, TinyChain::ConnectionHandler, host, port, @connections, @log)
      end
    end

    def start_timer
      interval = EVENT_INTERVAL
      [:ping, :getblock].each do |func|
        timers[func] = EM.add_periodic_timer(interval, method("work_#{func}"))
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
        EM.connect(host, port, TinyChain::ConnectionHandler, 
                   host, port, connections, log)
      else
        log.info { "max connections has been reached" }
      end
    end
    
  end
  
end

connections = []
log = Log4r::Logger.new(__FILE__)

if $0 == __FILE__
  case ARGV[0]
  when 'server' then
    node = TinyChain::Node.new("127.0.0.1", 9991, connections, log)
    log.info { 'running echo server on 9991' }
    node.run()
  else
    EM.run do
      host = "127.0.0.1"
      port = 9991
      TinyChain::ConnectionHandler.connect_peer(host, port, connections, log)
    end
  end
end
