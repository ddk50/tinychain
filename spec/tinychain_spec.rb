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

  
  
end
