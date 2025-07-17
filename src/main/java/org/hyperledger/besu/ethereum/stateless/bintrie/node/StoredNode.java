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
import org.hyperledger.besu.ethereum.stateless.bintrie.factory.NodeFactory;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.NodeVisitor;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents a regular node that can possibly be stored in storage.
 *
 * <p>StoredNodes wrap regular nodes and loads them lazily from storage as needed.
 *
 * @param <K> The type of the node's key.
 * @param <V> The type of the node's value.
 */
public class StoredNode<K extends BitSequence<K>, V> extends Node<K, V> {
  final NodeFactory<K, V> nodeFactory;
  Optional<Node<K, V>> loadedNode;

  /**
   * Constructs a new StoredNode at location.
   *
   * @param nodeFactory The node factory for creating nodes from storage.
   * @param location The location in the tree.
   */
  public StoredNode(final NodeFactory<K, V> nodeFactory, final Optional<K> location) {
    super(location);
    this.nodeFactory = nodeFactory;
    loadedNode = Optional.empty();
  }

  /**
   * Constructs a new StoredNode at location.
   *
   * @param nodeFactory The node factory for creating nodes from storage.
   * @param location The location in the tree.
   * @param commitment The node's commitment.
   */
  public StoredNode(
      final NodeFactory<K, V> nodeFactory,
      final Optional<K> location,
      final Optional<Bytes32> commitment) {
    super(location, commitment);
    this.nodeFactory = nodeFactory;
    loadedNode = Optional.empty();
  }

  /**
   * Accept a visitor to perform operations on the node.
   *
   * @param visitor The visitor to accept.
   * @return The result of the visitor's operation.
   */
  @Override
  public Node<K, V> accept(NodeVisitor<K, V> visitor) {
    final Node<K, V> node = load();
    return node.accept(visitor);
  }

  /**
   * Set node's location
   *
   * @param newLocation The new location for the Node
   * @return The updated Node
   */
  @Override
  public StoredNode<K, V> setLocation(Optional<K> newLocation) {
    StoredNode<K, V> result = new StoredNode<K, V>(nodeFactory, newLocation);
    result.loadedNode = loadedNode.map(x -> x.setLocation(newLocation));
    return result;
  }

  /**
   * Set node's commitment
   *
   * @param newCommitment The new commitment for the Node
   * @return The updated Node
   */
  @Override
  public StoredNode<K, V> setCommitment(Optional<Bytes32> newCommitment) {
    StoredNode<K, V> result = new StoredNode<K, V>(nodeFactory, location, newCommitment);
    result.loadedNode = loadedNode.map(x -> x.setCommitment(newCommitment));
    return result;
  }

  /**
   * Replace node's Location recursively.
   *
   * @param newLocation The new location for the Node
   * @return The updated Node
   */
  @Override
  public StoredNode<K, V> replaceLocation(K newLocation) {
    StoredNode<K, V> result = new StoredNode<K, V>(nodeFactory, Optional.of(newLocation));
    result.loadedNode = loadedNode.map(x -> x.replaceLocation(newLocation));
    return result;
  }

  /**
   * Get the encoded value of the node.
   *
   * @return The encoded value of the node.
   */
  @Override
  public Bytes encode() {
    throw new RuntimeException("Should load StoredNode before getEncodedValue");
  }

  /**
   * Get the encoded value of the node.
   *
   * @return The encoded value of the node.
   */
  @Override
  public Bytes getEncodedValue() {
    throw new RuntimeException("Should load StoredNode before getEncodedValue");
  }

  /**
   * Get a string representation of the node.
   *
   * @return A string representation of the node.
   */
  @Override
  public String print() {
    return String.format("Stored %s", location);
  }

  /**
   * Generates DOT representation for the StoredNode.
   *
   * @return DOT representation of the StoredNode.
   */
  @Override
  public String toDot(Boolean showNullNodes) {
    return "\n" + getName() + location.map(x -> x.toHexString()).orElse("");
  }

  Optional<Node<K, V>> retrieve(K location) {
    return nodeFactory.retrieve(location);
  }

  Node<K, V> load() {
    if (location.isEmpty()) {
      throw new RuntimeException("Cannot load a StoredNode with empty location");
    }
    K loc = location.get();
    if (loadedNode.isEmpty()) {
      loadedNode = retrieve(loc);
    }
    if (loadedNode.isPresent()) {
      return loadedNode.get();
    } else if (loc.length() == Node.KEY_SIZE) {
      return NullLeafNode.node();
    } else {
      return NullNode.node();
    }
  }
}
