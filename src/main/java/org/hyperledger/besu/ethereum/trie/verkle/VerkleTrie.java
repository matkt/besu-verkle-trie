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

import org.hyperledger.besu.ethereum.trie.NodeUpdater;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.ethereum.trie.verkle.node.Node;

/** Verkle Trie. */
public interface VerkleTrie<K, V> {

  /**
   * Returns an {@code Optional} of value mapped to the hash if it exists; otherwise empty.
   *
   * @param key The key for the value.
   * @return an {@code Optional} of value mapped to the hash if it exists; otherwise empty
   */
  Optional<V> get(K key);

  Optional<Node<V>> getNode(K key);

    /**
   * Updates the value mapped to the specified key, creating the mapping if one does not already
   * exist.
   *
   * @param key The key that corresponds to the value to be updated.
   * @param value The value to associate the key with.
   * @return Optional previous value before replacement if it exists.
   */
  Optional<V> put(K key, V value);

  /**
   * Deletes the value mapped to the specified key, if such a value exists (Optional operation).
   *
   * @param key The key of the value to be deleted.
   */
  void remove(K key);

  /**
   * Returns the hash of the root node of the trie.
   *
   * @return The hash of the root node of the trie.
   */
  Bytes32 getRootHash();

  /**
   * Commits any pending changes to the underlying storage.
   *
   * @param nodeUpdater used to store the node values
   */
  void commit(NodeUpdater nodeUpdater);
}
