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
package org.hyperledger.besu.ethereum.stateless.bintrie.visitor;

import org.hyperledger.besu.ethereum.stateless.bintrie.BitSequence;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.InternalNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.LeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.Node;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.NullLeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.NullNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.StemNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.ValueNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.Blake3Digest;

/**
 * Class representing a visitor for traversing nodes in a Trie tree to find a node based on a path.
 *
 * @param <K> The type of node's location.
 * @param <V> The type of node values.
 */
public class HashVisitor<K extends BitSequence<K>, V> implements NodeVisitor<K, V> {
  public final BitSequence<K> path;
  private int depth;

  public HashVisitor(final BitSequence<K> path) {
    if (path == null) {
      throw new IllegalArgumentException("HashVisitor's path cannot be null");
    }
    if (path.length() > Node.KEY_SIZE) {
      throw new IllegalArgumentException(
          String.format("HashVisitor's path's size cannot be more than %s", Node.KEY_SIZE));
    }
    this.path = path;
    this.depth = -1;
  }

  public int getDepth() {
    return depth;
  }

  /**
   * Visits a internalNode to determine the node matching a given path.
   *
   * @param internalNode The internalNode being visited.
   * @return The matching node or NULL_NODE_RESULT if not found.
   */
  @Override
  public Node<K, V> visit(InternalNode<K, V> internalNode) {
    if (!internalNode.isDirty() && internalNode.commitment.isPresent()) {
      return internalNode;
    }
    Blake3Digest digest = new Blake3Digest(Node.COMMITMENT_SIZE);

    Node<K, V> left = internalNode.left.accept(this);
    byte[] leftCommitment = left.commitment.orElse(Node.EMPTY_COMMITMENT).toArray();
    digest.update(leftCommitment, 0, leftCommitment.length);

    Node<K, V> right = internalNode.left.accept(this);
    byte[] rightCommitment = right.commitment.orElse(Node.EMPTY_COMMITMENT).toArray();
    digest.update(rightCommitment, 0, rightCommitment.length);

    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    Optional<Bytes32> commitment = Optional.of(Bytes32.wrap(hash));

    return new InternalNode<K, V>(internalNode.location, commitment, left, right);
  }

  /**
   * Visits a stemNode to determine the node matching a given path.
   *
   * @param stemNode The stemNode being visited.
   * @return The matching node or NULL_NODE_RESULT if not found.
   */
  @Override
  public Node<K, V> visit(StemNode<K, V> stemNode) {
    if (!stemNode.isDirty() && stemNode.commitment.isPresent()) {
      return stemNode;
    }
    Blake3Digest digest = new Blake3Digest(Node.COMMITMENT_SIZE);
    List<Bytes> commitments = new ArrayList<>(StemNode.maxChild());
    byte[] hash = new byte[digest.getDigestSize()];

    // Visit leaves
    for (LeafNode<K, V> leafNode : stemNode.children) {
      LeafNode<K, V> newNode = leafNode.accept(this);
      commitments.add(newNode.commitment.orElse(Node.EMPTY_COMMITMENT));
    }

    // Compute valuesCommitment by explicitely rolling up commiments.
    while (commitments.size() > 1) {
      if (commitments.size() % 2 == 1) {
        commitments.add(Node.EMPTY_COMMITMENT);
      }
      List<Bytes> rolledUp = new ArrayList<>(commitments.size() / 2);
      for (int i = 0; i < commitments.size(); i += 2) {
        Bytes left = commitments.get(i);
        Bytes right = commitments.get(i + 1);
        if (left == Node.EMPTY_COMMITMENT && right == Node.EMPTY_COMMITMENT) {
          rolledUp.add(Node.EMPTY_COMMITMENT);
        } else {
          digest.update(left.toArray(), 0, left.size());
          digest.update(right.toArray(), 0, right.size());
          digest.doFinal(hash, 0);
          rolledUp.add(Bytes.wrap(hash));
          digest.reset();
        }
      }
      commitments = rolledUp;
    }

    // H(stem + 0x00 + valuesCommitment)
    byte[] stemBytes = stemNode.stem.toBytes();
    byte[] valuesCommitment = commitments.get(0).toArray();
    digest.update(stemBytes, 0, stemBytes.length);
    digest.update((byte) 0);
    digest.update(valuesCommitment, 0, valuesCommitment.length);
    digest.doFinal(hash, 0);
    Optional<Bytes32> commitment = Optional.of(Bytes32.wrap(hash));
    return stemNode.setCommitment(commitment);
  }

  /**
   * Visits a NullNode to determine the matching node based on a given path.
   *
   * @param nullNode The NullNode being visited.
   * @return The NULL_NODE_RESULT since NullNode represents a missing node on the path.
   */
  @Override
  public Node<K, V> visit(NullNode<K, V> nullNode) {
    depth++;
    return nullNode;
  }

  /**
   * Visits a ValueNode to determine the matching node based on a given path.
   *
   * @param valueNode The NullNode being visited.
   * @return The NULL_NODE_RESULT since NullNode represents a missing node on the path.
   */
  @Override
  public LeafNode<K, V> visit(ValueNode<K, V> valueNode) {
    depth++;
    Optional<Bytes32> commitment =
        valueNode.value.map(val -> (Bytes32) valueNode.valueSerializer.apply(val));
    return valueNode.setCommitment(commitment);
  }

  /**
   * Visits a NullLeafNode to determine the matching node based on a given path.
   *
   * @param nullLeafNode The NullNode being visited.
   * @return The NULL_NODE_RESULT since NullNode represents a missing node on the path.
   */
  @Override
  public LeafNode<K, V> visit(NullLeafNode<K, V> nullLeafNode) {
    depth++;
    return nullLeafNode;
  }
}
