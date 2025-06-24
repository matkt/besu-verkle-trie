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
package org.hyperledger.besu.ethereum.stateless.bintrie.node;

import org.hyperledger.besu.ethereum.stateless.bintrie.BitSequence;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.NodeVisitor;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents a leaf node in the Verkle Trie.
 *
 * @param <K> The type of node's location.
 * @param <V> The type of the node's value.
 */
public abstract class LeafNode<K extends BitSequence<K>, V> extends Node<K, V> {
  public final Optional<V> value; // Value associated with the node

  /** Constructs a new Node with empty defaults. */
  public LeafNode() {
    super();
    value = Optional.empty();
  }

  /**
   * Constructs a new located Node with yet unset commitment.
   *
   * @param location The location of the node in the trie.
   */
  public LeafNode(final Optional<BitSequence<K>> location) {
    super(location);
    value = Optional.empty();
  }

  /**
   * Constructs a new Node
   *
   * @param location The location of the node in the trie.
   * @param value The node's value.
   */
  public LeafNode(final Optional<BitSequence<K>> location, final Optional<V> value) {
    super(location);
    this.value = value;
  }

  /**
   * Constructs a new Node
   *
   * @param location The location of the node in the trie.
   * @param value The node's value.
   */
  public LeafNode(
      final Optional<BitSequence<K>> location,
      final Optional<V> value,
      final Optional<Bytes32> commitment) {
    super(location, commitment);
    this.value = value;
  }

  /**
   * Accepts a visitor for generic node operations.
   *
   * @param visitor The node visitor.
   * @return The result of the visitor's operation.
   */
  @Override
  public abstract LeafNode<K, V> accept(NodeVisitor<K, V> visitor);

  @Override
  public abstract LeafNode<K, V> replaceLocation(BitSequence<K> newLocation);
}
