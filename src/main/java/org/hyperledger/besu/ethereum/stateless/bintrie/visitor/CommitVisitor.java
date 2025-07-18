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
import org.hyperledger.besu.ethereum.trie.NodeUpdater;

import org.apache.tuweni.bytes.Bytes;

/**
 * Class representing a visitor for traversing nodes in a Trie tree to find a node based on a path.
 *
 * @param <K> The type of node's location.
 * @param <V> The type of node values.
 */
public class CommitVisitor<K extends BitSequence<K>, V> implements NodeVisitor<K, V> {
  /** The NodeUpdater used to store changes in the Trie structure. */
  protected final NodeUpdater nodeUpdater;

  public CommitVisitor(final NodeUpdater nodeUpdater) {
    this.nodeUpdater = nodeUpdater;
  }

  /**
   * Visits a internalNode.
   *
   * @param internalNode The internalNode being visited.
   * @return The matching node or NULL_NODE_RESULT if not found.
   */
  @Override
  public Node<K, V> visit(InternalNode<K, V> internalNode) {
    if (!internalNode.isDirty()) {
      return internalNode;
    }
    if (internalNode.commitment.isEmpty()) {
      throw new RuntimeException("Cannot persist node without commitment");
    }
    if (internalNode.location.isEmpty()) {
      throw new RuntimeException("Cannot persist node without location");
    }
    Bytes loc = Bytes.wrap(internalNode.location.get().encode());
    internalNode.left.accept(this);
    internalNode.right.accept(this);
    System.out.println(
        String.format(
            "Storing Internal %s -> %s -> %s",
            internalNode.location.get().toHexString(), loc, internalNode.getEncodedValue()));
    nodeUpdater.store(loc, null, internalNode.getEncodedValue());
    internalNode.markClean();
    return internalNode;
  }

  /**
   * Visits a stemNode.
   *
   * @param stemNode The stemNode being visited.
   * @return The matching node or NULL_NODE_RESULT if not found.
   */
  @Override
  public Node<K, V> visit(StemNode<K, V> stemNode) {
    if (!stemNode.isDirty()) {
      return stemNode;
    }
    if (stemNode.commitment.isEmpty()) {
      throw new RuntimeException("Cannot persist node without commitment");
    }
    if (stemNode.location.isEmpty()) {
      throw new RuntimeException("Cannot persist node without location");
    }
    for (int i = 0; i < StemNode.maxChild(); ++i) {
      stemNode.child(i).accept(this);
    }
    Bytes key = Bytes.wrap(stemNode.stem.encode());
    System.out.println(
        String.format(
            "Storing Stem %s -> %s -> %s",
            stemNode.location.get().toHexString(), key, stemNode.getEncodedValue()));
    nodeUpdater.store(key, null, stemNode.getEncodedValue());
    stemNode.markClean();
    K location = stemNode.location.get();
    if (location.length() == 0) {
      nodeUpdater.store(Bytes.wrap(location.encode()), null, Bytes.wrap(stemNode.stem.toBytes()));
    }
    return stemNode;
  }

  /**
   * Visits a NullNode.
   *
   * @param nullNode The NullNode being visited.
   * @return The NULL_NODE_RESULT since NullNode represents a missing node on the path.
   */
  @Override
  public Node<K, V> visit(NullNode<K, V> nullNode) {
    return nullNode;
  }

  /**
   * Visits a ValueNode.
   *
   * @param valueNode The NullNode being visited.
   * @return The NULL_NODE_RESULT since NullNode represents a missing node on the path.
   */
  @Override
  public LeafNode<K, V> visit(ValueNode<K, V> valueNode) {
    if (!valueNode.isDirty()) {
      return valueNode;
    }
    if (valueNode.location.isEmpty()) {
      throw new RuntimeException("Cannot persist node without location");
    }
    Bytes key = Bytes.wrap(valueNode.location.get().encode());
    System.out.println(
        String.format(
            "Storing Value %s -> %s -> %s",
            valueNode.location.get().toHexString(), key, valueNode.getEncodedValue()));
    nodeUpdater.store(key, null, valueNode.getEncodedValue());
    valueNode.markClean();
    return valueNode;
  }

  /**
   * Visits a NullLeafNode.
   *
   * @param nullLeafNode The NullNode being visited.
   * @return The NULL_NODE_RESULT since NullNode represents a missing node on the path.
   */
  @Override
  public LeafNode<K, V> visit(NullLeafNode<K, V> nullLeafNode) {
    return nullLeafNode;
  }
}
