# -*- coding: utf-8 -*-

require_relative './spec_helper'

describe Bip38,"#encrypt" do
	context "WIF> 5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR" do
		address = '1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB'
		wif = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"
		passphrase = "TestingOneTwoThree"
		encrypted = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"    
    it "returns encrypted key" do
      expect(Bip38.encrypt(wif,passphrase,address)).to eq(encrypted)
      expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
      expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
      expect(Bip38.decrypt(encrypted,passphrase,address)).to eq(wif)
    end
  end

  context "No compression, no EC multiply" do
    context "WIF> 5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5" do
      wif = "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"
      passphrase = "Satoshi"
      encrypted = "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"
      it "returns encrypted key" do
        expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
        expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
      end
    end

    context "WIF> 5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR" do
  		passphrase = "TestingOneTwoThree"
  		encrypted = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
  		wif = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"
      it "returns encrypted key" do
        expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
        expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
      end
    end

    context "WIF> 5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5" do
  		passphrase = "Satoshi"
  		encrypted = "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"
  		wif = "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"
      it "returns encrypted key" do
        expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
        expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
      end
    end

    context "WIF> 5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4" do
      # Note: The non-standard UTF-8 characters in this passphrase should be NFC normalized to result in a passphrase of 0xcf9300f0909080f09f92a9 before further processing
      passphrase = "ϓ␀𐐀💩"
      normalized_passphrase = "\u03D2\u0301\u0000\U00010400\U0001F4A9"
      encrypted = "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn"
      wif = "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4"
      # it "returns encrypted key with normalized_passphrase" do
      #   expect(Bip38.encrypt(wif,normalized_passphrase)).to eq(encrypted)
      #   expect(Bip38.decrypt(encrypted,normalized_passphrase)).to eq(wif)
      # end
      # it "returns encrypted key with " do
      #   expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
      #   expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
      # end
    end
  end

  context "Compression, no EC multiply" do
    context "Compression, no EC multiply WIF> L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP" do
      passphrase = "TestingOneTwoThree"
      encrypted = "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"
      wif = "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP"
      hex = "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5"
      # it "returns encrypted key" do
      #   expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
      #   expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
      # end
    end

    context "Compression, no EC multiply WIF> KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7" do
      passphrase = "Satoshi"
      encrypted = "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7"
      wif = "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"
      hex = "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE"
    #   it "returns encrypted key" do
    #     expect(Bip38.encrypt(wif,passphrase)).to eq(encrypted)
    #     expect(Bip38.decrypt(encrypted,passphrase)).to eq(wif)
    #   end
    end
  end
end
