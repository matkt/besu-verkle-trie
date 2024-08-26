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
package org.hyperledger.besu.ethereum.trie.verkle.visitor;
import org.hyperledger.besu.ethereum.trie.verkle.VerkleTrieNodeTracker;
import org.hyperledger.besu.ethereum.trie.verkle.node.InternalNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.LeafNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.Node;
import org.hyperledger.besu.ethereum.trie.verkle.node.NullLeafNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.NullNode;
import org.hyperledger.besu.ethereum.trie.verkle.node.StemNode;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

/**
 * A visitor for inserting or updating values in a Verkle Trie.
 *
 * <p>This class implements the PathNodeVisitor interface and is used to visit and modify nodes in
 * the Verkle Trie while inserting or updating a value associated with a specific path.
 *
 * @param <V> The type of values to insert or update.
 */
public class PutVisitor<V> implements PathNodeVisitor<V> {
  private final V value;
  private Bytes visited; // add consumed bytes to visited
  private Optional<V> oldValue;

  private final Optional<VerkleTrieNodeTracker<V>> verkleTrieNodeTracker;

  /**
   * Constructs a new PutVisitor with the provided value to insert or update.
   *
   * @param value The value to be inserted or updated in the Verkle Trie.
   */
  public PutVisitor(final V value, final Optional<VerkleTrieNodeTracker<V>> verkleTrieNodeTracker) {
    this.value = value;
      this.visited = Bytes.EMPTY;
    this.oldValue = Optional.empty();
    this.verkleTrieNodeTracker = verkleTrieNodeTracker;
  }

  /**
   * Visits a branch node to insert or update a value associated with the provided path.
   *
   * @param internalNode The internal node to visit.
   * @param path The path associated with the value to insert or update.
   * @return The updated branch node with the inserted or updated value.
   */
  @Override
  public Node<V> visit(final InternalNode<V> internalNode, final Bytes path) {
    assert path.size() < 33;
    final byte index = path.get(0);
    visited = Bytes.concatenate(visited, Bytes.of(index));
    final Node<V> child = internalNode.child(index);
    final Node<V> updatedChild = internalNode.child(index).accept(this, path.slice(1));
    if (child instanceof NullNode<V> || child instanceof NullLeafNode<V>) {
      verkleTrieNodeTracker.ifPresent(
          processor -> processor.addNodeToBatch(updatedChild));
    }
    internalNode.replaceChild(index, updatedChild);
    if (updatedChild.isDirty()) {
      verkleTrieNodeTracker.ifPresent(
          processor -> processor.addNodeToBatch(internalNode));
      internalNode.markDirty();
    }
    return internalNode;
  }

  /**
   * Visits a stem node to insert or update a value associated with the provided path.
   *
   * @param stemNode The stem node to visit.
   * @param path The path associated with the value to insert or update.
   * @return The updated branch node with the inserted or updated value.
   */
  @Override
  public Node<V> visit(final StemNode<V> stemNode, final Bytes path) {
    assert path.size() < 33;
    final Bytes location = stemNode.getLocation().get();
    final Bytes stem = stemNode.getStem();
    final Bytes fullPath = Bytes.concatenate(location, path);
    final Bytes newStem = fullPath.slice(0, stem.size());
    if (stem.compareTo(newStem) == 0) { // Same stem => skip to leaf in StemNode
      final byte index = fullPath.get(newStem.size());
      visited = Bytes.concatenate(newStem, Bytes.of(index));
      final Node<V> child = stemNode.child(index);
      final Node<V> updatedChild = stemNode.child(index).accept(this, fullPath);
      if (child instanceof NullNode<V> || child instanceof NullLeafNode<V>) {
        // This call may lead to the removal of the node from the batch if a null node is inserted.
        verkleTrieNodeTracker.ifPresent(
            processor -> processor.addNodeToBatch(updatedChild));
      }
      stemNode.replaceChild(index, updatedChild);
      if (updatedChild.isDirty()) {
        verkleTrieNodeTracker.ifPresent(
            processor -> processor.addNodeToBatch(stemNode));
        stemNode.markDirty();
      }
      return stemNode;
    } else { // Divergent stems => push the stem node one level deeper
      InternalNode<V> newNode = new InternalNode<V>(location);
      newNode.setPrevious(stemNode.getPrevious());
      final int depth = location.size();
      StemNode<V> updatedStemNode = stemNode.replaceLocation(stem.slice(0, depth + 1));
      verkleTrieNodeTracker.ifPresent(
          processor -> processor.addNodeToBatch(updatedStemNode));

      newNode.replaceChild(stem.get(depth), updatedStemNode);
      updatedStemNode.markDirty();
      verkleTrieNodeTracker.ifPresent(
          processor -> processor.addNodeToBatch(newNode));
      newNode.markDirty();
      return newNode.accept(this, path);
    }
  }

  /**
   * Visits a leaf node to insert or update a value associated with the provided path.
   *
   * @param leafNode The leaf node to visit.
   * @param path The path associated with the value to insert or update.
   * @return The updated leaf node with the inserted or updated value.
   */
  @Override
  public Node<V> visit(final LeafNode<V> leafNode, final Bytes path) {
    assert path.size() < 33;
    LeafNode<V> newNode;
    oldValue = leafNode.getValue();
    if (oldValue != value) {
      newNode = new LeafNode<>(leafNode.getLocation(), value, oldValue);
      verkleTrieNodeTracker.ifPresent(
          processor -> processor.addNodeToBatch(newNode));
      newNode.markDirty();
    } else {
      newNode = leafNode;
    }
    visited = Bytes.EMPTY;
    return newNode;
  }

  /**
   * Visits a null node to insert or update a value associated with the provided path.
   *
   * @param nullNode The null node to visit.
   * @param path The path associated with the value to insert or update.
   * @return A new leaf node containing the inserted or updated value.
   */
  @Override
  public Node<V> visit(final NullNode<V> nullNode, final Bytes path) {
    assert path.size() < 33;
    // Replace NullNode with a StemNode and visit it
    final Bytes leafKey = Bytes.concatenate(visited, path);
    final StemNode<V> stemNode = new StemNode<V>(visited, leafKey);
    final Node<V> updatedNode = stemNode.accept(this, path);
    verkleTrieNodeTracker.ifPresent(
        processor -> processor.addNodeToBatch(updatedNode));
    updatedNode.markDirty();
    return updatedNode;
  }

  /**
   * Visits a null leaf node to insert a value associated with the provided path.
   *
   * @param nullLeafNode The null leaf node to visit.
   * @param path The path associated with the value to insert or update.
   * @return A new leaf node containing the inserted or updated value.
   */
  @Override
  public Node<V> visit(final NullLeafNode<V> nullLeafNode, final Bytes path) {
    assert path.size() < 33;
    oldValue = Optional.empty();
    LeafNode<V> newNode = new LeafNode<>(visited, value);
    verkleTrieNodeTracker.ifPresent(processor -> processor.addNodeToBatch(newNode));
    newNode.markDirty();
    visited = Bytes.EMPTY;
    return newNode;
  }

  /**
   * Return the old value that was replaced, or optional empty if none.
   *
   * @return Previous value before put, or empty.
   */
  public Optional<V> getOldValue() {
    return oldValue;
  }
}
