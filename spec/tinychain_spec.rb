require 'spec_helper'

describe Tinychain do

  context "when the genesis hash has been given" do

    before do
      @genesis = Tinychain::Block.new_genesis()
    end
    
    describe '#to_sha256hash_s' do
      it 'should make the genesis block as sha256' do
        expect(@genesis.to_sha256hash_s()).to eq(Tinychain::GENESIS_HASH)
      end
    end

    describe '#to_sha256hash' do
      it 'should make the genesis block sha256hash as binary' do
        expect(@genesis.to_sha256hash).to eq(Tinychain::GENESIS_HASH.to_i(16))
      end
    end

    describe '#to_json' do
      it 'should convert the genesis block to json' do
        jsonstr=<<JSON
{"type":"block","height":0,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","nonce":1264943,"bit":26229296,"time":1458902575,"jsonstr":""}
JSON
        jsonstr.chomp!
        expect(@genesis.to_json).to eq(jsonstr)
      end
    end

    describe '#to_binary_s' do
      it 'should convert the genesis block to binary' do
        binary = Tinychain::BlkBlock.new(nonce: Tinychain::GENESIS_NONCE, block_id: 0,
                                         time: Tinychain::GENESIS_TIME, bits: Tinychain::GENESIS_BITS,
                                         prev_hash: 0, strlen: 0, payloadstr: "")
        expect(@genesis.to_binary_s).to eq(binary.to_binary_s)
      end
    end

  end

  context "when a bad json has been given" do
    describe "#parse_json" do
      it 'should be raise a error' do
        json = "{\"type\" : \"aaaa\"}"        
        expect{ Tinychain::Block.parse_json(json) }.to raise_error(Tinychain::InvalidUnknownFormat)
      end
    end
  end
  
  context "when a good json has been given" do
    describe "#parse_json" do
      it 'should accept the json string' do
        jsonstr=<<JSON
{ 
  "type": "block",
  "height": 0,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "nonce": 1264943,
  "bit": 26229296,
  "time": 1458902575,
  "jsonstr": ""
}
JSON
        block = Tinychain::Block.parse_json(jsonstr)
        expect(block.prev_hash).to eq(0)
        expect(block.height).to eq(0)
        expect(block.nonce).to eq(1264943)
        expect(block.time).to eq(1458902575)
        expect(block.jsonstr).to eq("")
      end
    end
  end 

  describe "BlockChain" do  

    before :each do
      @hash = []      
      @hash[0] = "0000000000000000000000000000000000000000000000000000000000000000"
      @hash[1] = "0000000000000000000000000000000000000000000000000000000000000001"
      @hash[2] = "0000000000000000000000000000000000000000000000000000000000000002"
      @hash[3] = "0000000000000000000000000000000000000000000000000000000000000003"
      @hash[4] = "0000000000000000000000000000000000000000000000000000000000000004"
      @hash[5] = "0000000000000000000000000000000000000000000000000000000000000005"
      @hash[6] = "0000000000000000000000000000000000000000000000000000000000000006"
      @hash[7] = "0000000000000000000000000000000000000000000000000000000000000007"
      @hash[8] = "0000000000000000000000000000000000000000000000000000000000000008"
      @hash[9] = "0000000000000000000000000000000000000000000000000000000000000009"
      @hash[10] = "0000000000000000000000000000000000000000000000000000000000000010"
      
      
      @genesis_block = Tinychain::TestBlock.new(@hash[0], @hash[1])      
      @blockchain = Tinychain::BlockChain.new(@genesis_block)
    end

    context "when blocks has been given" do
      describe "#add_block" do
        it 'should add blocks' do
          block = Tinychain::TestBlock.new(@hash[1], @hash[2])
          expect(@blockchain.add_block(@hash[1], block)).to eq(block)

          block = Tinychain::TestBlock.new(@hash[2], @hash[3])
          expect(@blockchain.add_block(@hash[2], block)).to eq(block)

          block = Tinychain::TestBlock.new(@hash[3], @hash[4])
          expect(@blockchain.add_block(@hash[3], block)).to eq(block)
        end
      end

      describe "#find_block_by_hash" do
        it 'should find out a block' do
          block1 = Tinychain::TestBlock.new(@hash[1], @hash[2])
          @blockchain.add_block(@hash[1], block1)
          block2 = Tinychain::TestBlock.new(@hash[2], @hash[3])
          @blockchain.add_block(@hash[2], block2)
          block3 = Tinychain::TestBlock.new(@hash[3], @hash[4])
          @blockchain.add_block(@hash[3], block3)
          
          ret = @blockchain.find_winner_block_head()
          expect(ret.to_sha256hash_s).to eq(@hash[4])
        end
      end
      
    end

    context "when blockchain has branches" do
      describe "#find_winner_block_head" do
        it 'should find out the winner block' do
          block = Tinychain::TestBlock.new(@hash[1], @hash[2])
          @blockchain.add_block(@hash[1], block)
          block = Tinychain::TestBlock.new(@hash[2], @hash[3])
          @blockchain.add_block(@hash[2], block)
          block = Tinychain::TestBlock.new(@hash[3], @hash[4])
          @blockchain.add_block(@hash[3], block)

          ##
          ## branch at the block 3
          ##
          block = Tinychain::TestBlock.new(@hash[3], @hash[4])
          @blockchain.add_block(@hash[3], block)
          block = Tinychain::TestBlock.new(@hash[3], @hash[5])
          @blockchain.add_block(@hash[3], block)
          block = Tinychain::TestBlock.new(@hash[3], @hash[6])
          @blockchain.add_block(@hash[3], block)

          ##
          ## Winner!
          ##
          block = Tinychain::TestBlock.new(@hash[6], @hash[7])
          @blockchain.add_block(@hash[6], block)
          block = Tinychain::TestBlock.new(@hash[7], @hash[8])
          @blockchain.add_block(@hash[7], block)

          ret = @blockchain.find_winner_block_head()
          expect(ret.to_sha256hash_s).to eq(@hash[8])
        end
      end

      describe "#find_block_by_hash" do
        it 'should find out the block' do
          
          block = Tinychain::TestBlock.new(@hash[1], @hash[2])
          @blockchain.add_block(@hash[1], block)
          block = Tinychain::TestBlock.new(@hash[2], @hash[3])
          @blockchain.add_block(@hash[2], block)
          block = Tinychain::TestBlock.new(@hash[3], @hash[4])
          @blockchain.add_block(@hash[3], block)

          ##
          ## branch at the block 3
          ##
          block = Tinychain::TestBlock.new(@hash[3], @hash[4])
          @blockchain.add_block(@hash[3], block)
          block = Tinychain::TestBlock.new(@hash[3], @hash[5])
          @blockchain.add_block(@hash[3], block)
          block = Tinychain::TestBlock.new(@hash[3], @hash[6])
          @blockchain.add_block(@hash[3], block)

          ##
          ## Winner!
          ##
          block = Tinychain::TestBlock.new(@hash[6], @hash[7])
          @blockchain.add_block(@hash[6], block)
          block = Tinychain::TestBlock.new(@hash[7], @hash[8])
          @blockchain.add_block(@hash[7], block)

          ret = @blockchain.find_block_by_hash(@hash[6])
          expect(ret.to_sha256hash_s).to eq(@hash[6])
          
        end
      end

    end

  end
  
end
