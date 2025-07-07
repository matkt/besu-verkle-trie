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
import org.hyperledger.besu.ethereum.stateless.bintrie.node.Node;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.NullNode;
import org.hyperledger.besu.ethereum.stateless.bintrie.node.StemNode;

/**
 * Class representing a visitor for flattening a node in a Trie tree.
 *
 * <p>Flattening a node means that it is merged with its parent, adding one level to the extension
 * path. Per current specs, only StemNodes can have extensions, so only StemNodes can potentially be
 * flattened.
 *
 * @param <K> The type of node keys.
 * @param <V> The type of node values.
 */
public class FlattenVisitor<K extends BitSequence<K>, V> implements NodeVisitor<K, V> {
  @Override
  public Node<K, V> visit(InternalNode<K, V> internalNode) {
    final Node<K, V> left = internalNode.left.accept(this);
    final Node<K, V> right = internalNode.right.accept(this);

    final boolean leftIsNull = left instanceof NullNode;
    final boolean rightIsNull = right instanceof NullNode;
    final boolean leftIsStem = left instanceof StemNode;
    final boolean rightIsStem = right instanceof StemNode;

    // All null -> null
    if (leftIsNull && rightIsNull) {
      return NullNode.nullNode();
    }
    // Unchanged -> no-op
    if (left == internalNode.left && right == internalNode.right) {
      return internalNode;
    }
    // Null and Stem : push stem up
    if (leftIsNull && rightIsStem) {
      return right.replaceLocation(internalNode.location.get());
    }
    if (leftIsStem && rightIsNull) {
      return left.replaceLocation(internalNode.location.get());
    }
    return new InternalNode<K, V>(internalNode.location, left, right);
  }

  // Optional<Boolean> onlyChildBranch = internalNode.findOnlyChild();
  // if (onlyChildBranch.isEmpty()) {
  // return internalNode;
  // }
  // final boolean branch = onlyChildBranch.get();
  // Node<K, V> child = internalNode.child(branch).accept(this);
  //
  // // N+I -> do not flatten, N+S -> flatten
  // if (child instanceof InternalNode) {
  // return internalNode.replaceChild(branch, child);
  // } else if (child instanceof StemNode) {
  // Optional<BitSequence<K>> loc = child.location.map(x -> x.slice(0, x.length()
  // - 1));
  // return child.setLocation(loc);
  // } else if (child instanceof NullNode) {
  // return
  // } else {
  // throw new NotImplementedException("Unknown node type");
  // }
  // }

  @Override
  public Node<K, V> visit(StemNode<K, V> stemNode) {
    if (stemNode.allLeavesAreNull()) {
      return NullNode.nullNode();
    }
    return stemNode;
  }
}
