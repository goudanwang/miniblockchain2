# PoS Blockchain CTF - Long Range Attack Challenge

This is a Capture The Flag (CTF) challenge based on a Proof-of-Stake (PoS) blockchain that is vulnerable to long-range attacks.

## Challenge Description

You are presented with a simple PoS blockchain where validators are selected based on their stake. Your goal is to exploit the long-range attack vulnerability to steal the treasure (1,000,000 coins) and obtain the flag.

### The Vulnerability

The PoS implementation has a critical flaw in its validator selection mechanism:

1. **No Finality**: Old blocks can be replaced with alternative versions
2. **Timestamp Manipulation**: Validator selection depends on timestamps that can be manipulated
3. **Weak Randomness**: The "randomness" for validator selection is deterministic based on previous block hash and timestamp
4. **No Checkpointing**: There's no mechanism to prevent rewriting ancient history

### Attack Vector: Long Range Attack

A long-range attack exploits the fact that:
1. An attacker who once had stake (even small amounts) can rewrite history from that point
2. By trying different timestamps, the attacker can find ones where they are selected as validator
3. The attacker can create an alternative chain where they control the treasure
4. If this alternative chain is longer than the main chain, it will be accepted

## Setup Instructions

### Prerequisites

```bash
pip install flask rsa
```

### Running the Challenge

1. Start the server:
```bash
python pos_blockchain_ctf.py
```

2. Access the challenge at:
```
http://localhost:5000/a1b2c3d4e5f6g/
```

(Replace `a1b2c3d4e5f6g` with any valid URL prefix from the code)

## Challenge Endpoints

- `/` - Main page showing blockchain state
- `/flag` - Get the flag (requires controlling the treasure)
- `/submit_block` - Submit new blocks to the blockchain
- `/get_attacker_key` - Get the attacker's private key for signing
- `/validator_info` - Information about validator selection
- `/reset` - Reset the blockchain state
- `/source_code` - View the source code

## Solution Strategy

1. **Understand the Current State**: Examine the blockchain to see current balances and UTXOs
2. **Identify the Vulnerability**: The validator selection algorithm is deterministic and can be manipulated
3. **Plan the Attack**: 
   - Start from genesis block where attacker has initial stake
   - Create transaction transferring treasure to attacker
   - Find timestamp where attacker is selected as validator
   - Sign the malicious block with attacker's key
4. **Execute the Attack**: Submit the alternative blockchain history
5. **Claim the Flag**: Once controlling the treasure, get the flag

## Key Files

- `pos_blockchain_ctf.py` - Main CTF challenge implementation
- `long_range_attack_exploit.py` - Example exploit script
- `README.md` - This documentation

## Educational Value

This challenge demonstrates:
- How PoS consensus mechanisms work
- The importance of finality in blockchain systems
- Why checkpointing and other safety mechanisms are crucial
- How deterministic randomness can be exploited
- The concept of long-range attacks in PoS systems

## Real-World Relevance

Long-range attacks are a well-known issue in PoS systems. Real PoS blockchains address this through:
- **Checkpointing**: Periodic finalization of blocks
- **Weak Subjectivity**: Requiring recent state for validation
- **Slashing**: Penalizing malicious validators
- **Economic Finality**: Making attacks economically unfeasible

## Hints for Solving

1. The attacker starts with 50 coins of stake
2. Validator selection depends on: `hash(prev_block_hash + timestamp) % total_stake`
3. Try different timestamps to find when the attacker is selected
4. You need to create a longer chain than the current main chain
5. The treasure UTXO can be found in the genesis block
6. Use the `/get_attacker_key` endpoint to get signing capabilities

## Flag Format

`DDCTF{P0S_L0ng_R@ng3_[4 hex chars]Att@ck_[3 hex chars][4 hex chars]}`

The flag is dynamically generated based on the genesis block hash and URL prefix.

## Difficulty Level

**Intermediate** - Requires understanding of:
- Blockchain mechanics
- Digital signatures
- PoS consensus
- Long-range attack concepts

Good luck, and happy hacking! 🚀
