use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Valid;
use ministark::merkle::Error;
use ministark::merkle::MatrixMerkleTree;
use ministark::merkle::MerkleProof;
use ministark::merkle::MerkleTree;
use ministark::merkle::MerkleTreeConfig;
use ministark::merkle::MerkleTreeImpl;
use ministark::utils::SerdeOutput;
use ministark::Matrix;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ruint::aliases::U256;
use sandstorm_claims::sharp::merkle::HashedLeafConfig;
use sandstorm_claims::sharp::merkle::MerkleTreeVariantProof;
use sandstorm_claims::sharp::merkle::UnhashedLeafConfig;
use sha2::Digest;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::iter::zip;
use std::marker::PhantomData;
use std::rc::Rc;

/// Batched merkle proof as per SHARP verifier
pub struct BatchedMerkleProof<C: MerkleTreeConfig> {
    pub nodes: Vec<SerdeOutput<C::Digest>>,
    pub initial_leaves: Vec<C::Leaf>,
    pub sibling_leaves: Vec<C::Leaf>,
    pub height: usize,
}

impl<C: MerkleTreeConfig> BatchedMerkleProof<C> {
    /// Generates a batched proof for an ordered list of unique indices and
    /// corresponding merkle proofs.
    ///
    /// This follows how SHARP batches merkle proofs for StarkWare's L1 verifier
    ///
    /// # Panics
    /// Panics if:
    /// - the indices/proofs are empty
    /// - length of proofs and indices are different
    /// - proofs come from different height merkle trees
    /// - indices are not sorted or unique
    /// - indices are out of range
    pub fn from_proofs(proofs: &[MerkleProof<C>], indices: &[usize]) -> Self {
        assert_eq!(proofs.len(), indices.len());
        assert!(!proofs.is_empty());

        // sanity checks on proofs and indices
        let height = proofs[0].height();
        println!("height: {height}");
        assert!(proofs.iter().all(|p| p.height() == height));
        assert!(indices.windows(2).all(|w| w[0] < w[1]));
        let num_leaves = 1 << height;
        assert!(indices.iter().all(|&i| i < num_leaves));

        // change leaf indices to indices into a binary tree as array
        let binary_tree_indices: Vec<usize> = {
            let shift = 1 << height;
            indices.iter().map(|i| i + shift).collect()
        };

        let mut node_queue = VecDeque::new();
        let mut leaf_queue = VecDeque::from_iter(zip(&binary_tree_indices, proofs));

        // handle leaf nodes layer and build the initial node queue
        let mut initial_leaves = Vec::new();
        let mut sibling_leaves = Vec::new();
        while let Some((index, proof)) = leaf_queue.pop_front() {
            initial_leaves.push(proof.leaf().clone());
            node_queue.push_back((index >> 1, proof.path()));

            if let Some(&(next_index, next_proof)) = leaf_queue.front() {
                if are_siblings(*index, *next_index) {
                    initial_leaves.push(next_proof.leaf().clone());
                    leaf_queue.pop_front();
                    continue;
                }
            }

            sibling_leaves.push(proof.sibling().clone());
        }

        // handle non leaf nodes
        let mut nodes = Vec::new();
        while let Some((index, node_path)) = node_queue.pop_front() {
            let (node, path_remainder) = node_path.split_first().unwrap();

            if index > 2 {
                assert!(!path_remainder.is_empty());
                node_queue.push_back((index >> 1, path_remainder))
            }

            if let Some(&(next_index, _)) = node_queue.front() {
                if are_siblings(index, next_index) {
                    node_queue.pop_front();
                    continue;
                }
            }

            nodes.push(node.clone());
        }

        Self {
            nodes,
            initial_leaves,
            sibling_leaves,
            height,
        }
    }

    // fn into_proofs(self, indices: &[usize]) -> Vec<MerkleProof<C>> {
    //     let n = self.initial_leaves.len();
    //     assert_eq!(self.initial_leaves.len(), n);

    //     assert!(indices.windows(2).all(|w| w[0] < w[1]));
    //     let num_leaves = 1 << self.height;
    //     assert!(indices.iter().all(|&i| i < num_leaves));

    //     // change leaf indices to indices into a binary tree as array
    //     let binary_tree_indices: Vec<usize> = {
    //         let shift = 1 << self.height;
    //         indices.iter().map(|i| i + shift).collect()
    //     };

    //     let leaves = self.initial_leaves;
    //     let mut node_queue = VecDeque::new();
    //     let mut leaf_queue = VecDeque::from_iter(zip(&binary_tree_indices,
    // &leaves));

    //     // reconstruct leaves and siblings
    //     let mut siblings = Vec::new();
    //     let mut paths = Vec::new();
    //     let mut sibling_leaves = self.sibling_leaves.into_iter();
    //     while let Some((index, leaf)) = leaf_queue.pop_front() {
    //         if let Some(&(next_index, next_leaf)) = leaf_queue.front() {
    //             if are_siblings(*index, *next_index) {
    //                 siblings.push(next_leaf.clone());
    //                 siblings.push(leaf.clone());
    //                 let node = C::hash_leaves(leaf, next_leaf);

    //                 let path = Rc::new(RefCell::new(vec![]));
    //                 paths.push(path.clone());
    //                 paths.push(path.clone());
    //                 node_queue.push_back((index >> 1, path));
    //                 leaf_queue.pop_front();
    //                 continue;
    //             }
    //         }

    //         let sibling = sibling_leaves.next().unwrap();
    //         let node = if index % 2 == 0 {
    //             C::hash_leaves(leaf, &sibling)
    //         } else {
    //             C::hash_leaves(&sibling, leaf)
    //         };
    //         siblings.push(sibling);
    //         let path = Rc::new(RefCell::new(vec![node]));
    //         paths.push(path.clone());
    //         node_queue.push_back((index >> 1, path))
    //     }
    //     assert!(sibling_leaves.next().is_none());
    //     assert_eq!(leaves.len(), siblings.len());

    //     while let Some((index, path)) = node_queue.pop_front() {
    //         let path = path.borrow_mut();

    //         if let Some(&(next_index, next_path)) = node_queue.front() {
    //             if are_siblings(*index, *next_index) {
    //                 siblings.push(next_leaf.clone());
    //                 siblings.push(leaf.clone());
    //                 leaf_queue.pop_front();
    //                 continue;
    //             }
    //         }
    //     }

    //     // // reconstruct nodes
    //     // while let Some((index, proof)) = binary_tree_indices {
    //     //     initial_leaves.push(proof.leaf().clone());
    //     //     node_queue.push_back((index >> 1, proof.path()));

    //     //     if let Some(&(next_index, next_proof)) = leaf_queue.front() {
    //     //         if are_siblings(*index, *next_index) {
    //     //             initial_leaves.push(next_proof.leaf().clone());
    //     //             leaf_queue.pop_front();
    //     //             continue;
    //     //         }
    //     //     }

    //     //     sibling_leaves.push(proof.sibling().clone());
    //     // }

    //     // let paths = Vec::new();

    //     todo!()
    // }
}

fn are_siblings(i0: usize, i1: usize) -> bool {
    i0 ^ 1 == i1
}

pub enum MerkleProofsVariant<D: Digest + Send + Sync + 'static> {
    Hashed(Vec<MerkleProof<HashedLeafConfig<D>>>),
    Unhashed(Vec<MerkleProof<UnhashedLeafConfig<D>>>),
}

pub fn partition_proofs<D: Digest + Send + Sync + 'static>(
    proofs: &[MerkleTreeVariantProof<D>],
) -> MerkleProofsVariant<D> {
    let mut hash_proofs = Vec::new();
    let mut unhash_proofs = Vec::new();
    for proof in proofs.to_vec() {
        match proof {
            MerkleTreeVariantProof::Hashed(p) => hash_proofs.push(p),
            MerkleTreeVariantProof::Unhashed(p) => unhash_proofs.push(p),
        }
    }
    if hash_proofs.is_empty() {
        assert!(!unhash_proofs.is_empty());
        MerkleProofsVariant::Unhashed(unhash_proofs)
    } else if unhash_proofs.is_empty() {
        assert!(!hash_proofs.is_empty());
        MerkleProofsVariant::Hashed(hash_proofs)
    } else {
        unreachable!()
    }
}

mod tests {
    use super::BatchedMerkleProof;
    use ministark::merkle::MerkleTreeConfig;
    use sha2::digest::Output;
    use sha2::Digest;
    use sha3::Keccak256;

    #[test]
    fn batched_merkle_proof_from_two_proofs() -> Result<(), Error> {
        let leaves = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let merkle_tree = MerkleTreeImpl::<ByteMerkleTreeConfig>::new(leaves)?;
        let l0_proof = merkle_tree.prove(0)?;
        let l1_proof = merkle_tree.prove(1)?;

        let batch_proof = BatchedMerkleProof::from_proofs(&[l0_proof, l1_proof], &[0, 1]);

        Ok(())
    }

    struct ByteMerkleTreeConfig;

    impl MerkleTreeConfig for ByteMerkleTreeConfig {
        type Digest = Keccak256;
        type Leaf = u8;

        fn hash_leaves(l0: &u8, l1: &u8) -> Output<Keccak256> {
            Keccak256::digest([*l0, *l1])
        }
    }
}
