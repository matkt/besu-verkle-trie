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
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents a leaf node in the Verkle Trie.
 *
 * @param <K> The type of node's location.
 * @param <V> The type of the node's value.
 */
public class ValueNode<K extends BitSequence<K>, V> extends LeafNode<K, V> {
  public final Function<V, Bytes> valueSerializer;

  /**
   * Constructs a new ValueNode with location, value.
   *
   * @param location The location of the node in the tree.
   */
  public ValueNode(final Optional<K> location) {
    super(location, Optional.empty());
    valueSerializer = val -> (Bytes) val;
  }

  /**
   * Constructs a new ValueNode with location, value.
   *
   * @param location The location of the node in the tree.
   * @param value The value associated with the node.
   */
  public ValueNode(final Optional<K> location, final Optional<V> value) {
    super(location, value);
    this.valueSerializer = val -> (Bytes) val;
  }

  /**
   * Constructs a new ValueNode with location, value.
   *
   * @param location The location of the node in the tree.
   * @param value The value associated with the node.
   * @param valueSerializer Serializer for values.
   */
  public ValueNode(
      final Optional<K> location,
      final Optional<V> value,
      final Function<V, Bytes> valueSerializer) {
    super(location, value);
    this.valueSerializer = valueSerializer;
  }

  /**
   * Constructs a new ValueNode with location, value.
   *
   * @param location The location of the node in the tree.
   * @param commitment The node's commitment
   * @param value The value associated with the node.
   * @param valueSerializer Serializer for values.
   */
  public ValueNode(
      final Optional<K> location,
      final Optional<Bytes32> commitment,
      final Optional<V> value,
      final Function<V, Bytes> valueSerializer) {
    super(location, value, commitment);
    this.valueSerializer = valueSerializer;
  }

  /**
   * Accepts a visitor for generic node operations.
   *
   * @param visitor The node visitor.
   * @return The result of the visitor's operation.
   */
  @Override
  public LeafNode<K, V> accept(NodeVisitor<K, V> visitor) {
    return visitor.visit(this);
  }

  /**
   * Set node's Location
   *
   * @param newLocation The new location for the Node
   * @return The updated Node
   */
  @Override
  public ValueNode<K, V> setLocation(Optional<K> newLocation) {
    return this;
  }

  /**
   * Replaces recursively node's Location
   *
   * @param newLocation The new location for the Node
   * @return The updated Node
   */
  @Override
  public ValueNode<K, V> replaceLocation(final K newLocation) {
    return new ValueNode<K, V>(Optional.of(newLocation), value, valueSerializer);
  }

  /**
   * Set node's Commitment
   *
   * @param newCommitment The new commitment for the Node
   * @return The updated Node
   */
  @Override
  public ValueNode<K, V> setCommitment(final Optional<Bytes32> newCommitment) {
    if (newCommitment.equals(commitment)) {
      return this;
    }
    return new ValueNode<K, V>(location, newCommitment, value, valueSerializer);
  }

  /**
   * Get the RLP-encoded value of the node.
   *
   * @return The RLP-encoded value.
   */
  @Override
  public Bytes encode() {
    return value.map(valueSerializer).orElse(Bytes.EMPTY);
  }

  /**
   * Get a string representation of the node.
   *
   * @return A string representation of the node.
   */
  @Override
  public String print() {
    return "Value ["
        + location.map(loc -> loc.toBinaryString()).orElse(".")
        + "]: "
        + value.map(Object::toString).orElse("empty");
  }

  /**
   * Generates DOT representation for the ValueNode.
   *
   * @param showNullNodes Should include Null Nodes.
   * @return DOT representation of the ValueNode.
   */
  @Override
  public String toDot(Boolean showNullNodes) {
    return "\n"
        + getName()
        + location.map(x -> x.toHexString()).orElse("")
        + " [value="
        + value.map(valueSerializer).map(x -> x.toHexString()).orElse(null)
        + "]";
  }
}
