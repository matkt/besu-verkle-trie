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
package org.hyperledger.besu.ethereum.stateless.bintrie;

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.ethereum.stateless.bintrie.node.LeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.Node;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.NullNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.CommitVisitor;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.FlattenVisitor;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.GetVisitor;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.HashVisitor;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.PutVisitor;
import org.hyperledger.besu.ethereum.stateless.bintrie.visitor.RemoveVisitor;
import org.hyperledger.besu.ethereum.trie.NodeUpdater;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;

/**
 * A simple implementation of a Bin Trie. The batched version is recommended for better performance
 *
 * @param <K> The type of keys in the Bin Trie.
 * @param <V> The type of values in the Bin Trie.
 */
public class SimpleBinTrie<K extends BitSequence<K>, V> implements BinTrie<K, V> {
  protected Node<K, V> root;

  /** Creates a new Bin Trie with a null node as the root. */
  public SimpleBinTrie() {
    this.root = NullNode.node();
  }

  /**
   * Creates a new Bin Trie with the specified node as the root.
   *
   * @param root The root node of the Bin Trie.
   */
  public SimpleBinTrie(final Optional<Node<K, V>> root) {
    this.root = root.orElse(NullNode.node());
  }

  /**
   * Creates a new Bin Trie with the specified node as the root.
   *
   * @param root The root node of the Bin Trie.
   */
  public SimpleBinTrie(final Node<K, V> root) {
    this.root = root;
  }

  /**
   * Retrieves the root node of the Bin Trie.
   *
   * @return The root node of the Bin Trie.
   */
  public Node<K, V> getRoot() {
    return root;
  }

  /**
   * Gets the value associated with the specified key from the Bin Trie.
   *
   * @param key The key to retrieve the value for.
   * @return An optional containing the value if found, or an empty optional if not found.
   */
  @Override
  public Optional<V> get(final K key) {
    checkNotNull(key);
    Node<K, V> node = root.accept(new GetVisitor<K, V>(key));
    if (node instanceof LeafNode<K, V>) {
      return ((LeafNode<K, V>) node).value;
    }
    return Optional.empty();
  }

  /**
   * Inserts a key-value pair into the Bin Trie.
   *
   * @param key The key to insert.
   * @param value The value to associate with the key.
   */
  @Override
  public Optional<V> put(final K key, final V value) {
    checkNotNull(key);
    checkNotNull(value);
    final PutVisitor<K, V> kvPutVisitor = new PutVisitor<>(key, value);
    this.root = root.accept(kvPutVisitor);
    return kvPutVisitor.getOldValue();
  }

  /**
   * Removes a key-value pair from the Bin Trie.
   *
   * @param key The key to remove.
   */
  @Override
  public void remove(final K key) {
    checkNotNull(key);
    this.root = root.accept(new RemoveVisitor<K, V>(key));
  }

  /** Restructure tree to get minimal representation. */
  @Override
  public void flatten() {
    this.root = root.accept(new FlattenVisitor<K, V>());
  }

  /**
   * Computes and returns the root hash of the Bin Trie.
   *
   * @return The root hash of the Bin Trie.
   */
  @Override
  public Bytes32 getRootHash() {
    root = root.accept(new FlattenVisitor<K, V>());
    root = root.accept(new HashVisitor<K, V>());
    assert root.commitment.isPresent() : "HashVisitor should produce a rootHash";
    return root.commitment.get();
  }

  /**
   * Returns a string representation of the Bin Trie.
   *
   * @return A string in the format "SimpleBinTrie[RootHash]".
   */
  @Override
  public String toString() {
    return getClass().getSimpleName() + "[" + getRootHash() + "]";
  }

  /**
   * Commits the Bin Trie using the provided node updater.
   *
   * @param nodeUpdater The node updater for storing the changes in the Bin Trie.
   */
  @Override
  public void commit(final NodeUpdater nodeUpdater) {
    getRootHash();
    root = root.accept(new CommitVisitor<K, V>(nodeUpdater));
  }

  /**
   * Returns the DOT representation of the entire Bin Trie.
   *
   * @param showNullNodes if true displays NullNodes and NullLeafNodes; if false does not.
   * @return The DOT representation of the Bin Trie.
   */
  public String toDotTree(Boolean showNullNodes) {
    return String.format(
        "digraph BinTrie {\n%s\n}", getRoot().toDot(showNullNodes).replaceAll("^\\n+|\\n+$", ""));
  }

  /**
   * Returns the DOT representation of the entire Bin Trie.
   *
   * <p>The representation does not contain NullNodes and NullLeafNodes.
   *
   * @return The DOT representation of the Bin Trie.
   */
  public String toDotTree() {
    StringBuilder result = new StringBuilder("digraph BinTrie {");
    Node<K, V> root = getRoot();
    result.append(root.toDot());
    if (result.indexOf("NullNode") >= 0) {
      result.append("\nNullNode");
    }
    if (result.indexOf("NullLeafNode") >= 0) {
      result.append("\nNullLeafNode");
    }
    return result.append("\n}").toString();
  }
}
