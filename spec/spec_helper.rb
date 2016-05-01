$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'tinychain'

##
## 
##
module Tinychain
  class TestBlock

    attr_accessor :next
    attr_accessor :prev_hash
    attr_accessor :hash
    attr_accessor :bits

    def initialize(prev_hash, hash)
      @prev_hash = prev_hash
      @hash      = hash
      @next      = []
      @bits      = 0x1effffff
    end

    def to_sha256hash_s()
      return @hash
    end
    
  end
end
