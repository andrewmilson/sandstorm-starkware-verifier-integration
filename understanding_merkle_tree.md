Merkle tree:
                      H0
                   /     \
                H1          H2
             /   \         /   \
          H3      H4      H5     H6
         /  \    /  \    / \     / \
        L0  L1  L2  L3  L4  L5  L6  L7
Items:  ^^          ^^  ^^  ^^

proof of L0 contains:
   - L1
   - H4
   - H2

queue[0] = (8, L0)
queue[1] = (11, L3)
queue[2] = (12, L4)
queue[3] = (13, L5)

verifyMerkle() first round:
   - queueSize: 4
   - take first index from queue:
      - idx: 8, sibling: 8 ^ 1 = 9
      - sibling_offset: 1
      - rdIdx: 0 % queue_size
      - load queue[0].hash
      - rdIdx: 1 % queue_size
      - NOTE: queue[0].index >>= 1 (=4)
      - load next queue item index = 11
      - check if equal to sibling idx 
         - not equal (11 != 9) so load hash from proof
         - Store masked hash queue[0].hash = hash(LHS||RHS)
   - index is now 11
      - idx: 11, sibling: 11 ^ 1 = 10
      - sibling_offset: 0x0
      - rdIdx: 1
      - load queue[1].hash item: L3
      - rdIdx: 2
      - NOTE: queue[1].index >>= 1 (=5)
      - load next queue item index = 12
      - check if equal to sibling idx 
         - not equal (12 != 11) so load hash from proof
         - Store masked hash queue[1].hash = hash(LHS||RHS)
   - index is now 12
      - idx: 12, sibling: 12 ^ 1 = 13
      - sibling_offset: 1
      - rdIdx: 2
      - load queue[2].hash item: L4
      - rdIdx: 3
      - load next queue item index = 13
      - check if equal to sibling idx (YES!)
         - next hash comes from the queue
         - rdIdx: 4
         - load next queue item index = (rdIdx % queueSize = 0) = 4
         - Store masked hash queue[1].hash = hash(LHS||RHS)


round 2 merkle tree:
                      H0
                   /     \
                H1          H2
             /   \         /   \
          H3      H4      H5     H6
Items:    ^^      ^^      ^^
         /  \    /  \    / \     / \
        L0  L1  L2  L3  L4  L5  L6  L7

queue[0] = (4, H3)
queue[1] = (5, H4)
queue[2] = (6, L5)

verifyMerkle() first round:
   - first item (idx=4):
      - sibling idx: 5
      - load running hash
      - rdIdx = 0

