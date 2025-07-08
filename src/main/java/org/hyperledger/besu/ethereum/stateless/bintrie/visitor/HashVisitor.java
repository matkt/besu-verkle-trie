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
 * Class for gathering Trie's commitments.
 *
 * @param <K> The type of node's location.
 * @param <V> The type of node values.
 */
public class HashVisitor<K extends BitSequence<K>, V> implements NodeVisitor<K, V> {
  private final Blake3Digest digest = new Blake3Digest(Node.COMMITMENT_SIZE);

  public HashVisitor() {
    digest.reset();
  }

  private Bytes32 hash(Bytes32 value) {
    byte[] hash = new byte[digest.getDigestSize()];
    digest.reset();
    digest.update(value.toArray(), 0, value.size());
    digest.doFinal(hash, 0);
    Bytes32 result = (Bytes32) Bytes.of(hash);
    digest.reset();
    return result;
  }

  private Bytes32 hash(Optional<Bytes32> left, Optional<Bytes32> right) {
    Bytes32 leftValue = left.orElse(Node.EMPTY_COMMITMENT);
    Bytes32 rightValue = right.orElse(Node.EMPTY_COMMITMENT);
    return hash(leftValue, rightValue);
  }

  private Bytes32 hash(Bytes32 leftValue, Bytes32 rightValue) {
    if (leftValue == Node.EMPTY_COMMITMENT && rightValue == Node.EMPTY_COMMITMENT) {
      return Node.EMPTY_COMMITMENT;
    }
    byte[] rawDigest = new byte[digest.getDigestSize()];
    digest.reset();
    digest.update(leftValue.toArray(), 0, leftValue.size());
    digest.update(rightValue.toArray(), 0, rightValue.size());
    digest.doFinal(rawDigest, 0);
    Bytes32 result = (Bytes32) Bytes.of(rawDigest);
    digest.reset();
    return result;
  }

  /**
   * Computes commitment for an internal node.
   *
   * @param internalNode The internalNode being visited.
   * @return The internalNode with computed commitment.
   */
  @Override
  public Node<K, V> visit(InternalNode<K, V> internalNode) {
    if (!internalNode.isDirty() && internalNode.commitment.isPresent()) {
      return internalNode;
    }

    Node<K, V> left = internalNode.left.accept(this);
    Node<K, V> right = internalNode.right.accept(this);
    Optional<Bytes32> newCommitment = Optional.of(hash(left.commitment, right.commitment));

    // System.out.println(
        // String.format(
            // "Internal commitment: %s -> %s",
            // internalNode.location.get().toBinaryString(), newCommitment));
    return new InternalNode<K, V>(internalNode.location, newCommitment, left, right);
  }

  /**
   * Computes commitment for a stem node.
   *
   * @param stemNode The stemNode being visited.
   * @return The stemNode with computed commitment.
   */
  @Override
  public Node<K, V> visit(StemNode<K, V> stemNode) {
    if (!stemNode.isDirty() && stemNode.commitment.isPresent()) {
      return stemNode;
    }

    List<LeafNode<K, V>> children = new ArrayList<>(StemNode.maxChild());
    List<Bytes32> commitments = new ArrayList<>(StemNode.maxChild());

    // Visit leaves
    for (LeafNode<K, V> leafNode : stemNode.children) {
      LeafNode<K, V> newNode = leafNode.accept(this);
      children.add(newNode);
      commitments.add(newNode.commitment.orElse(Node.EMPTY_COMMITMENT));
    }

    // Compute valuesCommitment by explicitely rolling up commiments.
    while (commitments.size() > 1) {
      if (commitments.size() % 2 == 1) {
        commitments.add(Node.EMPTY_COMMITMENT);
      }
      List<Bytes32> rolledUp = new ArrayList<>(commitments.size() / 2);
      for (int i = 0; i < commitments.size(); i += 2) {
        Bytes32 left = commitments.get(i);
        Bytes32 right = commitments.get(i + 1);
	Bytes32 rolledCommitment = hash(left, right);
	rolledUp.add(rolledCommitment);
        // if (rolledCommitment != Node.EMPTY_COMMITMENT) {
          // System.out.println(
              // String.format(
                  // "Stem commitment rolling up size %s, index %s:\n H(%s, %s)\n -> %s",
                  // commitments.size(), i, left, right, rolledCommitment)); 
	// }
      }
      commitments = rolledUp;
    }

    // System.out.println(String.format("Stem values commitment: %s", commitments.get(0)));
    // H(stem + 0x00 + valuesCommitment)
    Bytes32 stemBytes = Bytes32.rightPad(Bytes.of(stemNode.stem.toBytes()));
    Optional<Bytes32> newCommitment = Optional.of(hash(stemBytes, commitments.get(0)));
    // System.out.println(
        // String.format(
            // "Stem commitment: %s -> %s", Bytes.wrap(stemNode.stem.toBytes()), newCommitment));
    return new StemNode<K, V>(stemNode.location, stemNode.stem, newCommitment, children);
  }

  /**
   * Computes commitment for a null node.
   *
   * @param nullNode The nullNode being visited.
   * @return The nullNode, the commitment being already set.
   */
  @Override
  public Node<K, V> visit(NullNode<K, V> nullNode) {
    return nullNode;
  }

  /**
   * Computes commitment for a value node.
   *
   * @param valueNode The valueNode being visited.
   * @return The valueNode with computed commitment.
   */
  @Override
  public LeafNode<K, V> visit(ValueNode<K, V> valueNode) {
    Bytes32 valueSerialized = (Bytes32) valueNode.valueSerializer.apply(valueNode.value.get());
    Optional<Bytes32> newCommitment = Optional.of(hash(valueSerialized));
    // BitSequence<K> loc = valueNode.location.get();
    // System.out.println(
        // String.format(
            // "Value commitment at %s:\n %s -> %s", loc.toBinaryString(), valueSerialized, newCommitment));
    return valueNode.setCommitment(newCommitment);
  }

  /**
   * Computes commitment for a null leaf node.
   *
   * @param nullLeafNode The nullLeafNode being visited.
   * @return The nullLeafNode, the commitment being already set.
   */
  @Override
  public LeafNode<K, V> visit(NullLeafNode<K, V> nullLeafNode) {
    return nullLeafNode;
  }
}
