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
package org.hyperledger.besu.ethereum.stateless.bintrie.factory;

import org.hyperledger.besu.ethereum.stateless.bintrie.BitSequence;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.LeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.NullLeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.ValueNode;
import org.hyperledger.besu.ethereum.trie.NodeLoader;

import java.util.Optional;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * A factory for creating bintrie Trie nodes based on stored data.
 *
 * @param <K> The type of keys stored in bintrie Trie nodes.
 * @param <V> The type of values stored in bintrie Trie nodes.
 */
public class StoredValueNodeFactory<K extends BitSequence<K>, V> implements ValueNodeFactory<K, V> {
  private final NodeLoader nodeLoader;
  private final Function<Bytes, V> valueDeserializer;

  /**
   * Creates a new StoredValueNodeFactory with the given node loader and value deserializer.
   *
   * @param nodeLoader The loader for retrieving stored nodes.
   * @param valueDeserializer The function to deserialize values from Bytes.
   */
  public StoredValueNodeFactory(NodeLoader nodeLoader, Function<Bytes, V> valueDeserializer) {
    this.nodeLoader = nodeLoader;
    this.valueDeserializer = valueDeserializer;
  }

  /**
   * Retrieves a bintrie Trie node from stored data based on the location
   *
   * @param location Node's location
   * @return An optional containing the retrieved node, or an empty optional if the node is not
   *     found.
   */
  @Override
  public Optional<LeafNode<K, V>> retrieve(final K location) {
    Bytes32 hash = null; // For backward compatibilty purposes only.
    Optional<Bytes> maybeEncodedValues = nodeLoader.getNode(Bytes.wrap(location.encode()), hash);
    if (maybeEncodedValues.isEmpty()) {
      return Optional.empty();
    }
    Bytes encodedValue = maybeEncodedValues.get();
    if (encodedValue.isEmpty()) {
      return Optional.of(NullLeafNode.node());
    }
    V value = valueDeserializer.apply(encodedValue);
    return Optional.of(new ValueNode<K, V>(Optional.of(location), Optional.of(value)));
  }
}
