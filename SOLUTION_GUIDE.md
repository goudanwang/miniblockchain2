# Solution Guide - PoS Long Range Attack CTF

This guide explains how to solve the PoS blockchain CTF challenge that is vulnerable to long-range attacks.

## Understanding the Challenge

The challenge implements a simplified Proof-of-Stake blockchain with the following components:
- **Validators**: Entities that can create blocks based on their stake
- **UTXOs**: Unspent transaction outputs (similar to Bitcoin)
- **Stake-based Selection**: Validators are chosen based on their stake amount
- **Treasure**: 1,000,000 coins that the attacker needs to steal

## The Vulnerability

The PoS implementation has a critical flaw in validator selection:

```python
def select_validator(prev_block_hash, stakes, timestamp):
    seed = hash(prev_block_hash + str(timestamp))
    random_val = int(seed, 16) % total_stake
    # Select validator based on random_val and stakes
```

**Problems:**
1. **Deterministic**: Given the same inputs, always produces the same result
2. **Timestamp Manipulation**: Attacker can try different timestamps
3. **No Time Validation**: Old timestamps are accepted
4. **No Finality**: Old blocks can be replaced

## Attack Strategy

### Step 1: Understand the Initial State
- Genesis block contains treasure UTXO owned by `treasure_address`
- Attacker starts with 50 coins of stake
- Other validators have 300, 200, and 100 coins respectively

### Step 2: Long Range Attack Plan
1. **Historical Rewrite**: Start from genesis block
2. **Timestamp Manipulation**: Find timestamp where attacker is selected
3. **Malicious Transaction**: Create transaction transferring treasure to attacker
4. **Chain Building**: Build longer alternative chain
5. **Chain Replacement**: Submit longer chain to replace main chain

### Step 3: Implementation

#### A. Find Winning Timestamp
```python
def find_winning_timestamp(prev_hash, stakes, attacker_addr):
    for timestamp in range(start_time, start_time + 10000):
        if select_validator(prev_hash, stakes, timestamp) == attacker_addr:
            return timestamp
    return None
```

#### B. Create Malicious Transaction
```python
# Transfer treasure from treasure_address to attacker_address
steal_tx = create_tx(
    [treasure_utxo_id],  # Input: treasure UTXO
    [create_output_utxo(attacker_address, 1000000)],  # Output: to attacker
    treasure_privkey  # Sign with treasure's key (this is the challenge!)
)
```

**Wait!** The attacker doesn't have the treasure's private key...

#### C. Alternative Approach - Historical Manipulation

The real attack exploits the fact that in the genesis block, the attacker had some stake. The attacker can:

1. **Go back to genesis**: Start alternative chain from genesis
2. **Manipulate early blocks**: Create blocks where attacker gains more stake
3. **Build longer chain**: Continue building until chain is longer than main chain
4. **Include treasure theft**: In the alternative history, steal the treasure

### Step 4: Detailed Attack

```python
# 1. Find timestamp where attacker is selected after genesis
genesis_hash = session['genesis_block_hash']
stakes = {"attacker": 50, "validator1": 300, ...}
winning_timestamp = find_winning_timestamp(genesis_hash, stakes, attacker_addr)

# 2. Create block where attacker steals treasure
# This requires the treasure UTXO ID from genesis block
treasure_utxo = find_treasure_utxo_in_genesis()
steal_tx = create_tx([treasure_utxo['id']], [output_to_attacker], attacker_privkey)

# 3. Create and sign the malicious block
malicious_block = {
    'prev': genesis_hash,
    'validator': attacker_address,
    'timestamp': winning_timestamp,
    'transactions': [steal_tx],
    'signature': sign_block(block_hash, attacker_privkey)
}

# 4. Continue building chain to make it longer than main chain
# 5. Submit the alternative chain
```

## Key Insights

1. **Timestamp Flexibility**: The system accepts any timestamp, allowing historical manipulation
2. **Deterministic Selection**: Same inputs always produce same validator selection
3. **No Finality**: Old blocks can be replaced with alternatives
4. **Stake History**: Attacker's historical stake allows them to create valid alternative history

## Practical Steps

1. **Access the CTF**: Go to `http://localhost:5000/a1b2c3d4e5f6g/`
2. **Get Attacker Key**: Visit `/get_attacker_key` endpoint
3. **Analyze State**: Examine current blockchain via homepage
4. **Implement Attack**: Use the exploit script or manual approach
5. **Submit Blocks**: Use `/submit_block` endpoint
6. **Claim Flag**: Visit `/flag` once treasure is controlled

## Tools Provided

- `long_range_attack_exploit.py`: Automated exploit script
- `demo_vulnerability.py`: Demonstrates the core vulnerability
- `/get_attacker_key`: Provides attacker's private key
- `/validator_info`: Shows validator selection information

## Real-World Relevance

This attack demonstrates why real PoS systems implement:
- **Checkpointing**: Periodic finalization of blocks
- **Weak Subjectivity**: Requiring recent state for validation  
- **Slashing**: Penalizing malicious validators
- **Economic Security**: Making attacks prohibitively expensive
- **Better Randomness**: Using VRF or other secure random sources

## Flag Format

Successfully completing the attack will yield a flag in the format:
`DDCTF{P0S_L0ng_R@ng3_[hex]Att@ck_[hex]}`

Good luck! 🎯
