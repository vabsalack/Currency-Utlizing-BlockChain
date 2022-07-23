import sys
from time import time
from hashlib import sha256
from datetime import datetime
from urllib.parse import urlparse
from Crypto.PublicKey import RSA
from Crypto.Signature import *
import json


def generate_keys():
    key_object = RSA.generate(2048)
    private_key = key_object.export_key()
    public_key = key_object.public_key().export_key()


def addGenesisBlock():
    trans = [Transaction("me", "you", 100)]
    genesis = Block(trans, 5, 0)
    return genesis


class BlockChain:

    def __init__(self):
        self.chain = [addGenesisBlock()]
        self.pendingTransactions = []
        self.difficulty = 2
        self.minerRewards = 10;
        self.blockSize = 10
        self.nodes = set()

    def minePendingTransactions(self, miner):
        lenPT = len(self.pendingTransactions)
        if lenPT <= 1:
            print("NOt enough transactions to mine! (Must be > 1)")
            return
        for i in range(0, lenPT, self.blockSize):
            end = i + self.blockSize if i <= lenPT else lenPT
            transaction_slice = self.pendingTransactions[i:end]
            new_block = Block(transaction_slice, datetime.fromtimestamp(time()), len(self.chain))
            previous_hash = self.getLastBlock().block_hash
            new_block.prev_block_hash = previous_hash
            new_block.mineBlock(self.difficulty)
            self.chain.append(new_block)
        print("Mining Transactions Success!")

        miner_rewards = Transaction("Miner Rewards", miner, self.minerRewards)
        self.pendingTransactions = [miner_rewards]

    def getLastBlock(self):
        return self.chain[-1]

    def register_node(self, address):
        url_fragments = urlparse(address)
        self.nodes.add(url_fragments.netloc)

    def resolveConflicts(self):
        pass

    def addTransactions(self, sender, receiver, amount, key):
        if not sender or not receiver or not amount:
            print("Transaction error 1")
            return False

        transaction = Transaction(sender, receiver, amount)
        transaction.signTransaction(key)

        if not transaction.IsValidTransaction():
            print("transaction error 2")
            return False

        self.pendingTransactions.append(transaction)
        return len(self.chain) + 1

    def IsValidChain(self):
        for i in range(1, len(self.chain)):

            block_i = self.chain[i-1]
            block_i1 = self.chain[i]

            if not block_i1.hasValidTransactions():
                print("error 3")
                return False

            if not block_i1.block_hash == block_i1.calculateHash():
                print("error 4")
                return False

            if not block_i.prev_block_hash == block_i1.block_hash:
                print("error 5")
                return False

        return True

    def chain_JSON_encode(self):

        block_chain_json = []
        for block in self.chain:
            block_json = block.block_header.copy()
            block_json["hash"] = block.block_hash

            transactions = []
            for trans in block.transactions:
                trans_json = trans.transaction_header.copy()
                trans_json["hash"] = trans.hash
                transactions.append(trans_json)

            block_json["transactions"] = transactions
            block_chain_json.append(block_json)
        return block_chain_json

    def getBalance(self, person):
        balance = 0
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            for j in range(0, len(block.transactions)):
                transaction = block.transactions[j]
                if transaction.sender == person:
                    balance -= transaction.amount
                if transaction.receiver == person:
                    balance += transaction.amount
        return balance


class Block:
    def __init__(self, transactions, timestamp, block_number):
        self.block_number = block_number
        self.transactions = transactions
        self.timestamp = timestamp
        self.prev_block_hash = ""
        self.nonce = 0
        self.block_header = {"block_number": self.block_number,
                             "transactions": self.transactions,
                             "timestamp": self.timestamp,
                             "pre_block_hash": self.prev_block_hash,
                             "nonce": self.nonce}
        self.block_hash = self.calculateHash()

    def calculateHash(self):
        details = self.block_header
        details["transactions"] = "".join([i.hash for i in details["transactions"]])
        json_string = json.dumps(details, sort_keys=True).encode()
        hash_obj = sha256(json_string)
        return hash_obj.hexdigest()

    def mineBlock(self, difficulty):
        hash_puzzle = "".join([str(i) for i in range(difficulty)])
        while self.block_hash[:difficulty] != hash_puzzle:
            self.nonce += 1
            self.block_hash = self.calculateHash()
        print("Block Mined")

    def hasValidTransactions(self):
        for trans in self.transactions:
            if not trans.IsValidTransaction():
                return False
        return True


class Transaction:
    def __init__(self, sender, receiver, amount):
        """

        :param sender:  sender public key in str
        :param receiver: receiver public key in str
        :param amount:
        :return:
        """
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.date_time = datetime.fromtimestamp(time())
        self.transaction_header = {"sender": self.sender,
                                   "receiver": self.receiver,
                                   "amount": self.amount,
                                   "date_time": self.date_time}
        self.hash = self.calculateHash()

    def calculateHash(self):
        details = self.transaction_header
        json_string = json.dumps(details, sort_keys=True).encode()
        hash_object = sha256(json_string)
        return hash_object.hexdigest()

    def IsValidTransaction(self):
        check = [self.hash == self.calculateHash(), self.sender != self.receiver]
        if all(check):
            return True
        if not check[0]:
            print("Hash mismatch! Transaction tampered")
        if not check[1]:
            print("Sender cannot be receiver")
        return False

    def signTransaction(self, key):
        if not self.IsValidTransaction():
            print("Transaction tampered error!")
            return False

        if str(key.publickey().export_key()) != self.sender:
            print("Transaction attempt to be signed from another wallet")
            return False

        pkcs1_15.new(key)
        print("made signature!")
        return True










