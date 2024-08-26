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

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.ethereum.trie.NodeUpdater;
import org.hyperledger.besu.ethereum.trie.verkle.node.Node;
import org.hyperledger.besu.ethereum.trie.verkle.visitor.CommitVisitor;
import org.hyperledger.besu.ethereum.trie.verkle.visitor.GetVisitor;
import org.hyperledger.besu.ethereum.trie.verkle.visitor.PutVisitor;
import org.hyperledger.besu.ethereum.trie.verkle.visitor.RemoveVisitor;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * A simple implementation of a Verkle Trie.
 *
 * @param <K> The type of keys in the Verkle Trie.
 * @param <V> The type of values in the Verkle Trie.
 */
public class SimpleBatchedVerkleTrie<K extends Bytes, V extends Bytes>
    extends SimpleVerkleTrie<K, V> implements VerkleTrie<K, V> {

  protected final VerkleTrieNodeTracker<V> verkleTrieNodeTracker;

  public SimpleBatchedVerkleTrie(final VerkleTrieNodeTracker<V> verkleTrieNodeTracker) {
    super();
    this.verkleTrieNodeTracker = verkleTrieNodeTracker;
    this.verkleTrieNodeTracker.addNodeToBatch(this.root);
  }

  public SimpleBatchedVerkleTrie(
      final Node<V> providedRoot, final VerkleTrieNodeTracker<V> verkleTrieNodeTracker) {
    super(providedRoot);
    this.verkleTrieNodeTracker = verkleTrieNodeTracker;
    this.verkleTrieNodeTracker.addNodeToBatch(root);
  }

  public SimpleBatchedVerkleTrie(
      final Optional<Node<V>> maybeRoot, final VerkleTrieNodeTracker<V> verkleTrieNodeTracker) {
    super(maybeRoot);
    this.verkleTrieNodeTracker = verkleTrieNodeTracker;
    this.verkleTrieNodeTracker.addNodeToBatch(root);
  }

  @Override
  public Optional<V> get(final K key) {
    checkNotNull(key);
    return root.accept(new GetVisitor<V>(Optional.of(verkleTrieNodeTracker)), key).getValue();
  }

  @Override
  public Optional<Node<V>> getNode(final K key) {
    checkNotNull(key);
    return verkleTrieNodeTracker.getNodes(key);
  }


  @Override
  public Optional<V> put(final K key, final V value) {
    checkNotNull(key);
    checkNotNull(value);
    PutVisitor<V> visitor = new PutVisitor<>(value, Optional.of(verkleTrieNodeTracker));
    this.root = root.accept(visitor, key);
    return visitor.getOldValue();
  }

  @Override
  public void remove(final K key) {
    checkNotNull(key);
    this.root = root.accept(new RemoveVisitor<V>(Optional.of(verkleTrieNodeTracker)), key);
  }

  @Override
  public void commit(final NodeUpdater nodeUpdater) {
    verkleTrieNodeTracker.calculateStateRoot();
    root = root.accept(new CommitVisitor<V>(nodeUpdater), Bytes.EMPTY);
  }

  @Override
  public Bytes32 getRootHash() {
    verkleTrieNodeTracker.calculateStateRoot();
    return root.getHash().get();
  }
}
