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
import org.hyperledger.besu.ethereum.stateless.bintrie.BitSequenceFactory;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.InternalNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.LeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.Node;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.NullLeafNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.StemNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.StoredNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.ValueNode;
import org.hyperledger.besu.ethereum.trie.NodeLoader;

import java.util.ArrayList;
import java.util.List;
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
public class StoredNodeFactory<K extends BitSequence<K>, V> implements NodeFactory<K, V> {
  private final NodeLoader nodeLoader;
  private final BitSequenceFactory<K> keyFactory;
  private final Function<Bytes, V> valueDeserializer;

  /**
   * Creates a new StoredNodeFactory with the given node loader and value deserializer.
   *
   * @param nodeLoader The loader for retrieving stored nodes.
   * @param keyFactory The function to deserialize keys from Bytes.
   * @param valueDeserializer The function to deserialize values from Bytes.
   */
  public StoredNodeFactory(
      NodeLoader nodeLoader,
      BitSequenceFactory<K> keyFactory,
      Function<Bytes, V> valueDeserializer) {
    this.nodeLoader = nodeLoader;
    this.keyFactory = keyFactory;
    this.valueDeserializer = valueDeserializer;
  }

  /**
   * Retrieves a bintrie Trie node from stored data based on the location.
   *
   * @return An optional containing the retrieved node, or an empty optional if the node is not
   *     found.
   */
  @Override
  public Optional<Node<K, V>> retrieveRoot() {
    /*
     * Root node could be a NullNode, StemNode or InternalNode.
     * In case of StemNode, we store the stem at the root key,
     * and retrieve it by stem.
     * For the others, they work as usual.
     */
    Bytes rootKey = Bytes.wrap(keyFactory.empty().encode());
    Bytes32 hash = null; // For backward compatibilty purposes only.
    Optional<Bytes> maybeEncodedValues = nodeLoader.getNode(rootKey, hash);
    Bytes encodedValues = maybeEncodedValues.orElse(Bytes.EMPTY);
    System.out.println(String.format("Retrieving RootNode %s", encodedValues));
    K loc =
        encodedValues.size() == 31
            ? keyFactory.fromHexString(encodedValues.toHexString())
            : keyFactory.empty();
    return retrieve(loc);
  }

  /**
   * Retrieves a bintrie Trie node from stored data based on the location.
   *
   * @param location Node's location
   * @return An optional containing the retrieved node, or an empty optional if the node is not
   *     found.
   */
  @Override
  public Optional<Node<K, V>> retrieve(final K location) {
    /*
     * Currently, Root and Leaf are distinguishable by location.
     * To distinguish internal from stem, we further need values.
     * Currently, they are distinguished by values length.
     */
    System.out.println(String.format("Retrieving Node at location %s", location.toHexString()));
    Bytes32 hash = null; // For backward compatibilty purposes only.
    Optional<Bytes> maybeEncodedValues = nodeLoader.getNode(Bytes.wrap(location.encode()), hash);
    System.out.println(
        String.format("Retrieved %s -> %s", Bytes.wrap(location.encode()), maybeEncodedValues));
    if (maybeEncodedValues.isEmpty()) {
      return Optional.empty();
    }
    Bytes encodedValues = maybeEncodedValues.get();
    if (location.length() == Node.STEM_SIZE) {
      return Optional.of(decodeStemNode(location, encodedValues));
    } else {
      return Optional.of(decodeInternalNode(location, encodedValues));
    }
  }

  /**
   * Creates a internalNode using the provided location, and path.
   *
   * @param location The location of the internalNode.
   * @param encodedValues List of Bytes values retrieved from storage.
   * @return A internalNode instance.
   */
  InternalNode<K, V> decodeInternalNode(K location, Bytes encodedValues) {
    StoredNode<K, V> left, right;
    Optional<K> leftLocation, rightLocation;

    // Decode encodedValues
    System.out.println(String.format("EncodedValues: %s", encodedValues.toHexString()));
    int cursor = 0;
    Optional<Bytes32> commitment = Optional.of((Bytes32) encodedValues.slice(cursor, cursor + 32));
    cursor += 32;
    int leftExtensionLength = encodedValues.get(cursor);
    cursor += 1;
    Bytes leftExtension = encodedValues.slice(cursor, leftExtensionLength);
    cursor += leftExtensionLength;
    int rightExtensionLength = encodedValues.get(cursor);
    cursor += 1;
    Bytes rightExtension = encodedValues.slice(cursor, rightExtensionLength);
    cursor += rightExtensionLength;
    assert encodedValues.size() == cursor : "Unread bytes in stored InternalNode representation";

    leftLocation =
        Optional.of(
            (leftExtensionLength > 0)
                ? location.concatenate(leftExtension.toArray())
                : location.add(false));
    left = new StoredNode<K, V>(this, leftLocation, commitment);

    rightLocation =
        Optional.of(
            (rightExtensionLength > 0)
                ? location.concatenate(rightExtension.toArray())
                : location.add(true));
    right = new StoredNode<K, V>(this, rightLocation, commitment);

    return new InternalNode<K, V>(Optional.of(location), commitment, left, right);
  }

  /**
   * Creates a StemNode using the provided stem, hash and encodedValues
   *
   * @param stem The stem of the BranchNode.
   * @param encodedValues List of Bytes values retrieved from storage.
   * @return A BranchNode instance.
   */
  StemNode<K, V> decodeStemNode(K stem, Bytes encodedValues) {

    // Decode encodedValues
    int cursor = 0;
    Optional<Bytes32> commitment = Optional.of((Bytes32) encodedValues.slice(cursor, cursor + 32));
    cursor += 32;
    int depth = encodedValues.get(cursor);
    K location = stem.slice(0, depth);
    cursor += 1;
    List<LeafNode<K, V>> children = new ArrayList<>(StemNode.maxChild());
    for (int i = 0; i < StemNode.maxChild(); i++) {
      children.add(NullLeafNode.node());
    }
    while (encodedValues.size() > cursor) {
      int suffix = Byte.toUnsignedInt(encodedValues.get(cursor));
      V value = valueDeserializer.apply(encodedValues.slice(cursor + 1, 32));
      K loc = location.add(suffix, StemNode.maxChildWidth());
      children.set(suffix, new ValueNode<K, V>(Optional.of(loc), Optional.of(value)));
      cursor += 33;
    }
    assert encodedValues.size() == cursor : "Unread bytes in stored StemNode representation";

    System.out.println("Loaded StemNode location " + location.toHexString());
    return new StemNode<K, V>(Optional.of(location), stem, commitment, children);
  }
}
