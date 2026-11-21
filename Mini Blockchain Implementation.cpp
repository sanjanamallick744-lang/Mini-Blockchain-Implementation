
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstdint>
#include <cstring>

using namespace std;

// SHA-256 implementation
class SHA256 {
private:
    uint32_t state[8];

    static const uint32_t K[64];

    uint32_t rotateRight(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

public:
    SHA256() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }

    string hash(string input) {
        uint64_t bitLength = input.size() * 8;

        vector<unsigned char> data(
            input.begin(), input.end()
        );

        data.push_back(0x80);

        while (data.size() % 64 != 56)
            data.push_back(0x00);

        for (int i = 7; i >= 0; i--)
            data.push_back(
                (bitLength >> (i * 8)) & 0xff
            );

        for (size_t offset = 0;
             offset < data.size(); offset += 64) {

            uint32_t w[64];

            for (int i = 0; i < 16; i++) {
                int j = offset + i * 4;

                w[i] =
                    ((uint32_t)data[j] << 24) |
                    ((uint32_t)data[j + 1] << 16) |
                    ((uint32_t)data[j + 2] << 8) |
                    ((uint32_t)data[j + 3]);
            }

            for (int i = 16; i < 64; i++) {
                uint32_t s0 =
                    rotateRight(w[i - 15], 7) ^
                    rotateRight(w[i - 15], 18) ^
                    (w[i - 15] >> 3);

                uint32_t s1 =
                    rotateRight(w[i - 2], 17) ^
                    rotateRight(w[i - 2], 19) ^
                    (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 +
                       w[i - 7] + s1;
            }

            uint32_t a = state[0];
            uint32_t b = state[1];
            uint32_t c = state[2];
            uint32_t d = state[3];
            uint32_t e = state[4];
            uint32_t f = state[5];
            uint32_t g = state[6];
            uint32_t h = state[7];

            for (int i = 0; i < 64; i++) {
                uint32_t S1 =
                    rotateRight(e, 6) ^
                    rotateRight(e, 11) ^
                    rotateRight(e, 25);

                uint32_t ch =
                    (e & f) ^ (~e & g);

                uint32_t temp1 =
                    h + S1 + ch + K[i] + w[i];

                uint32_t S0 =
                    rotateRight(a, 2) ^
                    rotateRight(a, 13) ^
                    rotateRight(a, 22);

                uint32_t maj =
                    (a & b) ^ (a & c) ^ (b & c);

                uint32_t temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        stringstream result;

        for (int i = 0; i < 8; i++)
            result << hex << setfill('0')
                   << setw(8) << state[i];

        return result.str();
    }
};

const uint32_t SHA256::K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,
    0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,
    0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,
    0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,
    0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,
    0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,
    0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,
    0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,
    0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,
    0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,
    0xc67178f2
};

string calculateHash(string data) {
    SHA256 sha;
    return sha.hash(data);
}

// Block class
class Block {
public:
    int index;
    string timestamp;
    vector<string> transactions;
    string previousHash;
    string currentHash;

    Block(int idx, vector<string> tx,
          string prevHash) {

        index = idx;
        transactions = tx;
        previousHash = prevHash;

        time_t now = time(0);
        timestamp = ctime(&now);

        if (!timestamp.empty() &&
            timestamp[timestamp.size() - 1] == '\n')
            timestamp.erase(timestamp.size() - 1);

        currentHash = calculateHash(getData());
    }

    string getData() const {
        string data = to_string(index) + timestamp +
                      previousHash;

        for (size_t i = 0; i < transactions.size(); i++)
            data += transactions[i];

        return data;
    }

    void recalculateHash() {
        currentHash = calculateHash(getData());
    }

    void display() const {
        cout << "\n-----------------------------\n";
        cout << "Block Index: " << index << endl;
        cout << "Timestamp: " << timestamp << endl;
        cout << "Previous Hash: " << previousHash << endl;
        cout << "Current Hash: " << currentHash << endl;

        cout << "Transactions:\n";

        for (size_t i = 0; i < transactions.size(); i++)
            cout << "  " << transactions[i] << endl;
    }
};

// Blockchain class
class Blockchain {
private:
    vector<Block> chain;

public:
    Blockchain() {
        vector<string> initial;
        initial.push_back("Genesis Block Created");

        Block genesis(0, initial, "0");
        chain.push_back(genesis);
    }

    void addBlock(vector<string> transactions) {
        Block newBlock(
            chain.size(),
            transactions,
            chain.back().currentHash
        );

        chain.push_back(newBlock);

        cout << "\nBlock added successfully!\n";
        cout << "Block Hash: "
             << newBlock.currentHash << endl;
    }

    void displayChain() {
        cout << "\n========== BLOCKCHAIN ==========\n";

        for (size_t i = 0; i < chain.size(); i++)
            chain[i].display();
    }

    bool validateChain() {
        for (size_t i = 0; i < chain.size(); i++) {

            if (chain[i].currentHash !=
                calculateHash(chain[i].getData())) {
                return false;
            }

            if (i > 0 &&
                chain[i].previousHash !=
                chain[i - 1].currentHash) {
                return false;
            }
        }

        return true;
    }

    void tamperBlock(int index) {
        if (index <= 0 || index >= (int)chain.size()) {
            cout << "Invalid block index!\n";
            return;
        }

        chain[index].transactions[0] =
            "TAMPERED TRANSACTION";

        // Deliberately do not recalculate the hash.
        cout << "\nBlock data modified!\n";
        cout << "Run validation to detect tampering.\n";
    }

    int size() const {
        return chain.size();
    }
};

int main() {
    Blockchain blockchain;
    int choice;

    do {
        cout << "\n================================";
        cout << "\n       CHAINCORE BLOCKCHAIN";
        cout << "\n================================";
        cout << "\n1. Add New Block";
        cout << "\n2. Display Blockchain";
        cout << "\n3. Validate Blockchain";
        cout << "\n4. Simulate Tampering Attack";
        cout << "\n5. Exit";
        cout << "\nEnter choice: ";

        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(10000, '\n');
            cout << "Invalid input!\n";
            continue;
        }

        switch (choice) {
        case 1: {
            int n;
            vector<string> transactions;

            cout << "Number of transactions: ";
            if (!(cin >> n) || n < 1 || n > 100) {
                cin.clear();
                cin.ignore(10000, '\n');
                cout << "Enter a number from 1 to 100.\n";
                break;
            }

            cin.ignore(10000, '\n');

            for (int i = 0; i < n; i++) {
                string tx;
                cout << "Enter transaction "
                     << i + 1 << ": ";
                getline(cin, tx);

                transactions.push_back(tx);
            }

            blockchain.addBlock(transactions);
            break;
        }

        case 2:
            blockchain.displayChain();
            break;

        case 3:
            if (blockchain.validateChain())
                cout << "\nBlockchain is VALID!\n";
            else
                cout << "\nWARNING: Blockchain TAMPERED!\n";
            break;

        case 4: {
            int index;

            cout << "Enter block index to modify: ";
            cin >> index;

            blockchain.tamperBlock(index);
            break;
        }

        case 5:
            cout << "\nExiting ChainCore...\n";
            break;

        default:
            cout << "\nInvalid choice!\n";
        }

    } while (choice != 5);

    return 0;
}

