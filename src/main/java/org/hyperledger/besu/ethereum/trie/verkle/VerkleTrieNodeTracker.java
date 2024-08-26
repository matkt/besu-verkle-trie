/*
 * Copyright Hyperledger Besu Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.ethereum.trie.verkle;

import static org.hyperledger.besu.ethereum.trie.verkle.node.Node.getHighValue;
import static org.hyperledger.besu.ethereum.trie.verkle.node.Node.getLowValue;

import org.hyperledger.besu.ethereum.trie.verkle.hasher.Hasher;
import org.hyperledger.besu.ethereum.trie.verkle.hasher.PedersenHasher;
import org.hyperledger.besu.ethereum.trie.verkle.node.BranchNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.InternalNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.LeafNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.Node;
import org.hyperledger.besu.ethereum.trie.verkle.node.NullNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.StemNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.StoredNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Processes batches of trie nodes for efficient hashing.
 *
 * <p>This class manages the batching and hashing of trie nodes to optimize performance.
 */
public class VerkleTrieNodeTracker<V> {

  private static final Logger LOG = LogManager.getLogger(VerkleTrieNodeTracker.class);
  private static final int MAX_BATCH_SIZE = 1000; // Maximum number of nodes in a batch
  private static final Bytes[] EMPTY_ARRAY_TEMPLATE = new Bytes[0];
  private final Hasher hasher = new PedersenHasher(); // Hasher for node hashing
  private final Map<Bytes, Node<V>> touchNodes =
      new HashMap<>();
  private final List<Bytes> deletedNodes =
          new ArrayList<>();

  /**
   * Adds a node for future batching.
   *
   * @param node The node to add.
   */
  public void addNodeToBatch(final Node<V> node) {
    if(node instanceof StemNode<V> stemNode){
      touchNodes.put(stemNode.getStem(), node);
      deletedNodes.remove(stemNode.getStem());
      node.getLocation().ifPresent(
              location -> {
                touchNodes.remove(location);
                deletedNodes.add(location);
              });
    } else {
      node.getLocation().ifPresent(
              location -> {
                touchNodes.put(location, node);
                deletedNodes.remove(location);
              });
    }

  }

  public void removeNodeFromBatch(final Node<V> node) {
    if(node instanceof StemNode<V> stemNode){
      touchNodes.remove(stemNode.getStem());
      deletedNodes.add(stemNode.getStem());
    } else {
      node.getLocation().ifPresent(
              location -> {
                touchNodes.remove(location);
                deletedNodes.add(location);
              });
    }
  }

  /**
   * Returns the map of nodes currently added for future batching.
   *
   * @return Map of nodes to be batched.
   */
  public Map<Bytes, Node<V>> getNodesToBatch() {
    return touchNodes;
  }

  public Optional<Node<V>> getNodes(final Bytes key) {
    return Optional.ofNullable(touchNodes.get(key));
  }

  /**
   * Processes the nodes in batches. Sorts the nodes by their location and hashes them in batches.
   * Clears the batch after processing.
   */
  public void calculateStateRoot() {
    if (touchNodes.isEmpty()) {
      return;
    }

    final List<Map.Entry<Bytes, Node<V>>> sortedNodesByLocation =
        new ArrayList<>(touchNodes.entrySet());
    sortedNodesByLocation.sort(
        (entry1, entry2) -> Integer.compare(entry2.getKey().size(), entry1.getKey().size()));

    int currentDepth = -1; // Tracks the depth of the current batch

    final List<Node<V>> nodesInSameLevel = new ArrayList<>();
    for (Map.Entry<Bytes, Node<V>> entry : sortedNodesByLocation) {
      final Bytes location = entry.getKey();
      final Node<V> node = entry.getValue();
      if (node instanceof BranchNode<V>) {
        if (location.size() != currentDepth || nodesInSameLevel.size() > MAX_BATCH_SIZE) {
          if (!nodesInSameLevel.isEmpty()) {
            processBatch(nodesInSameLevel);
            nodesInSameLevel.clear();
          }
          if (location.isEmpty()) {
            // We will end up updating the root node. Once all the batching is finished,
            // we will update the previous states of the nodes by setting them to the new ones.
            calculateRootInternalNodeHash((InternalNode<V>) node);
            touchNodes.forEach(
                (__, n) -> {
                  if (n instanceof BranchNode<V>) {
                    n.setPrevious(n.getHash());
                  } else if (n instanceof LeafNode<V>) {
                    n.setPrevious(n.getValue());
                  }
                  n.markClean();
                });
            touchNodes.clear();
            return;
          }
          currentDepth = location.size();
        }
        if (node.isDirty() || node.getHash().isEmpty() || node.getCommitment().isEmpty()) {
          nodesInSameLevel.add(node);
        }
      }
    }

    throw new IllegalStateException("root node not found");
  }

  private void processBatch(List<Node<V>> nodes) {
    LOG.atTrace().log("Start hashing {} batch of nodes", nodes.size());
    List<Bytes> commitments = new ArrayList<>();

    LOG.atTrace().log("Creating commitments for stem nodes and internal nodes");
    for (final Node<V> node : nodes) {
      if (node instanceof StemNode<V>) {
        commitments.addAll(getStemNodeLeftRightCommitments((StemNode<V>) node));
      } else if (node instanceof InternalNode<V>) {
        commitments.addAll(getInternalNodeCommitments((InternalNode<V>) node));
      }
    }

    LOG.atTrace()
        .log(
            "Executing batch hashing for {} commitments of stem (left/right) and internal nodes.",
            commitments.size());
    Iterator<Bytes> commitmentsIterator = new ArrayList<>(commitments).iterator();
    Iterator<Bytes32> hashesIterator =
        hasher.hashMany(commitments.toArray(EMPTY_ARRAY_TEMPLATE)).iterator();

    // reset commitments list for stem
    commitments.clear();

    LOG.atTrace()
        .log("Creating commitments for stem nodes and refreshing hashes of internal nodes");
    for (final Node<V> node : nodes) {
      if (node instanceof StemNode<V>) {
        commitments.add(
            getStemNodeCommitment((StemNode<V>) node, commitmentsIterator, hashesIterator));
      } else if (node instanceof InternalNode<V>) {
        calculateInternalNodeHashes((InternalNode<V>) node, commitmentsIterator, hashesIterator);
      }
    }
    LOG.atTrace()
        .log("Executing batch hashing for {} commitments of stem nodes.", commitments.size());
    commitmentsIterator = commitments.iterator();
    hashesIterator = hasher.hashMany(commitments.toArray(EMPTY_ARRAY_TEMPLATE)).iterator();

    LOG.atTrace().log("Refreshing hashes of stem nodes");
    for (final Node<V> node : nodes) {
      if (node instanceof StemNode<V>) {
        calculateStemNodeHashes((StemNode<V>) node, commitmentsIterator, hashesIterator);
      }
    }
    LOG.atTrace().log("Finished refreshing hashes of stem nodes");
  }

  private void calculateRootInternalNodeHash(final InternalNode<V> internalNode) {
    final Bytes32 hash = Bytes32.wrap(getRootNodeCommitments(internalNode).get(0));
    internalNode.replaceHash(hash, hash);
  }

  private void calculateStemNodeHashes(
      final StemNode<V> stemNode,
      final Iterator<Bytes> commitmentsIterator,
      final Iterator<Bytes32> hashesIterator) {
    final Bytes32 hash = hashesIterator.next();
    final Bytes commitment = commitmentsIterator.next();
    stemNode.replaceHash(
        hash,
        commitment,
        stemNode.getLeftHash().orElseThrow(),
        stemNode.getLeftCommitment().orElseThrow(),
        stemNode.getRightHash().orElseThrow(),
        stemNode.getRightCommitment().orElseThrow());
  }

  private void calculateInternalNodeHashes(
      final InternalNode<V> internalNode,
      final Iterator<Bytes> commitmentsIterator,
      final Iterator<Bytes32> hashesIterator) {
    internalNode.replaceHash(hashesIterator.next(), commitmentsIterator.next());
  }

  private List<Bytes> getStemNodeLeftRightCommitments(StemNode<V> stemNode) {
    int size = StemNode.maxChild();
    List<Bytes> commitmentsHashes = new ArrayList<>();

    final List<Byte> leftIndices = new ArrayList<>();
    final List<Bytes> leftOldValues = new ArrayList<>();
    final List<Bytes> leftNewValues = new ArrayList<>();

    final List<Byte> rightIndices = new ArrayList<>();
    final List<Bytes> rightOldValues = new ArrayList<>();
    final List<Bytes> rightNewValues = new ArrayList<>();

    int halfSize = size / 2;

    for (int idx = 0; idx < size; idx++) {
      Node<V> node = stemNode.child((byte) idx);

      Optional<Bytes> oldValue = node.getPrevious().map(Bytes.class::cast);
      // We should not recalculate a node if it is persisted and has not undergone an update since
      // its last save.
      // If a child does not have a previous value, it means that it is a new node and we must
      // therefore recalculate it.
      if (!(node instanceof StoredNode<V>) && (oldValue.isEmpty() || node.isDirty())) {
        if (idx < halfSize) {
          leftIndices.add((byte) (2 * idx));
          leftIndices.add((byte) (2 * idx + 1));
          leftOldValues.add(getLowValue(oldValue));
          leftOldValues.add(getHighValue(oldValue));
          leftNewValues.add(getLowValue(node.getValue()));
          leftNewValues.add(getHighValue(node.getValue()));
        } else {
          rightIndices.add((byte) (2 * idx));
          rightIndices.add((byte) (2 * idx + 1));
          rightOldValues.add(getLowValue(oldValue));
          rightOldValues.add(getHighValue(oldValue));
          rightNewValues.add(getLowValue(node.getValue()));
          rightNewValues.add(getHighValue(node.getValue()));
        }
      }
    }

    if (!leftIndices.isEmpty()) {
      commitmentsHashes.add(
          hasher.commitUpdate(
              stemNode.getLeftCommitment(), leftIndices, leftOldValues, leftNewValues));
      leftIndices.clear();
      leftOldValues.clear();
      leftNewValues.clear();
    } else {
      commitmentsHashes.add(stemNode.getLeftCommitment().get());
    }
    if (!rightIndices.isEmpty()) {
      commitmentsHashes.add(
          hasher.commitUpdate(
              stemNode.getRightCommitment(), rightIndices, rightOldValues, rightNewValues));
      rightIndices.clear();
      rightOldValues.clear();
      rightNewValues.clear();
    } else {
      commitmentsHashes.add(stemNode.getRightCommitment().get());
    }

    return commitmentsHashes;
  }

  private Bytes getStemNodeCommitment(
      final StemNode<V> stemNode,
      final Iterator<Bytes> commitmentsIterator,
      final Iterator<Bytes32> iterator) {
    Bytes32[] hashes = new Bytes32[4];
    hashes[0] = Bytes32.rightPad(Bytes.of(1)); // extension marker
    hashes[1] = Bytes32.rightPad(stemNode.getStem());
    hashes[2] = iterator.next();
    hashes[3] = iterator.next();
    stemNode.replaceHash(
        null, null, hashes[2], commitmentsIterator.next(), hashes[3], commitmentsIterator.next());
    return hasher.commit(hashes);
  }

  private List<Bytes> getInternalNodeCommitments(InternalNode<V> internalNode) {
    int size = InternalNode.maxChild();
    final List<Bytes> commitmentsHashes = new ArrayList<>();

    final List<Byte> indices = new ArrayList<>();
    final List<Bytes> oldValues = new ArrayList<>();
    final List<Bytes> newValues = new ArrayList<>();
    for (int i = 0; i < size; i++) {
      final Node<V> node = internalNode.child((byte) i);
      Optional<Bytes> oldValue = node.getPrevious().map(Bytes.class::cast);
      // We should not recalculate a node if it is persisted and has not undergone an update since
      // its last save.
      // If a child does not have a previous value, it means that it is a new node and we must
      // therefore recalculate it.
      if (!(node instanceof StoredNode<V>) && (oldValue.isEmpty() || node.isDirty())) {
        indices.add((byte) i);
        oldValues.add(oldValue.orElse(Bytes.EMPTY));
        newValues.add(node.getHash().get());
      }
    }
    commitmentsHashes.add(
        hasher.commitUpdate(internalNode.getCommitment(), indices, oldValues, newValues));
    return commitmentsHashes;
  }

  private List<Bytes> getRootNodeCommitments(InternalNode<V> internalNode) {
    int size = InternalNode.maxChild();
    final List<Bytes> commitmentsHashes = new ArrayList<>();
    final List<Bytes> newValues = new ArrayList<>();
    for (int i = 0; i < size; i++) {
      final Node<V> node = internalNode.child((byte) i);
      newValues.add(node.getHash().get());
    }
    commitmentsHashes.add(hasher.commitRoot(newValues.toArray(new Bytes[] {})));
    return commitmentsHashes;
  }
}
