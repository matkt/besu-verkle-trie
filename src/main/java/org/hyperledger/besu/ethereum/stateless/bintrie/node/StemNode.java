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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents an internal node in a Binary Trie.
 *
 * @param <K> The type of node's location.
 * @param <V> The type of the node's value.
 */
public class StemNode<K extends BitSequence<K>, V> extends Node<K, V> {
  public final BitSequence<K> stem;
  public final List<LeafNode<K, V>> children;

  /**
   * Constructs a new BranchNode with location, hash, path, and children.
   *
   * @param location The location in the tree.
   * @param stem Node's stem.
   * @param commitment The node's commitment
   * @param children The list of children nodes.
   */
  public StemNode(
      final Optional<BitSequence<K>> location,
      final BitSequence<K> stem,
      final Optional<Bytes32> commitment,
      final List<LeafNode<K, V>> children) {
    super(location, commitment);
    this.stem = stem;
    this.children = children;
  }

  /**
   * Constructs a new BranchNode with location, hash, path, and children.
   *
   * @param location The location in the tree.
   * @param stem Node's stem.
   * @param children The list of children nodes.
   */
  public StemNode(
      final Optional<BitSequence<K>> location,
      final BitSequence<K> stem,
      final List<LeafNode<K, V>> children) {
    super(location);
    this.stem = stem;
    this.children = children;
  }

  /**
   * Constructs a new StemNode with optional location and path, initializing children to NullNodes.
   *
   * @param location The optional location in the tree.
   * @param stem Node's stem.
   */
  public StemNode(final Optional<BitSequence<K>> location, final BitSequence<K> stem) {
    super(location);
    this.stem = stem;

    List<LeafNode<K, V>> nullChildren = new ArrayList<>(maxChild());
    for (int i = 0; i < maxChild(); i++) {
      nullChildren.add(NullLeafNode.node());
    }
    this.children = nullChildren;
  }

  /**
   * Get the maximum number of children nodes (256 for byte indexes).
   *
   * @return The maximum number of children nodes.
   */
  public static int maxChild() {
    return 256;
  }

  /**
   * Accepts a visitor for generic node operations.
   *
   * @param visitor The node visitor.
   * @return The result of the visitor's operation.
   */
  @Override
  public Node<K, V> accept(NodeVisitor<K, V> visitor) {
    return visitor.visit(this);
  }

  /**
   * Get the child Node at given position
   *
   * @param suffix Position of the child Node
   * @return Child Node
   */
  public LeafNode<K, V> child(final int suffix) {
    return children.get(suffix);
  }

  /**
   * Replace child Node at given position
   *
   * @param suffix Position of child node
   * @param newChild New node.
   * @return the updated StemNode
   */
  public StemNode<K, V> replaceChild(int suffix, LeafNode<K, V> newChild) {
    List<LeafNode<K, V>> newChildren = new ArrayList<>(maxChild());
    for (int i = 0; i < maxChild(); i++) {
      newChildren.add(child(i));
    }
    newChildren.set(suffix, newChild);
    return new StemNode<K, V>(location, stem, commitment, newChildren);
  }

  /**
   * Set node's Location
   *
   * @param newLocation The new location for the Node
   * @return The updated Node
   */
  @Override
  public StemNode<K, V> setLocation(Optional<BitSequence<K>> newLocation) {
    return new StemNode<K, V>(newLocation, stem, commitment, children);
  }

  /**
   * Replace node's Location
   *
   * @param newLocation The new location for the Node
   * @return The updated Node
   */
  @Override
  public Node<K, V> replaceLocation(BitSequence<K> newLocation) {
    List<LeafNode<K, V>> newChildren = new ArrayList<>(maxChild());
    for (int i = 0; i < maxChild(); i++) {
      LeafNode<K, V> childNode = child(i);
      if (childNode instanceof NullLeafNode) {
	newChildren.add(childNode);
      } else {
        BitSequence<K> childLocation = newLocation.add(i);
        newChildren.add(child(i).replaceLocation(childLocation));
      }
    }
    return (Node<K, V>) new StemNode<K, V>(Optional.of(newLocation), stem, commitment, newChildren);
  }

  /**
   * Set node's commitment
   *
   * @param newCommitment The new commitment for the Node
   * @return The updated Node
   */
  @Override
  public Node<K, V> setCommitment(Optional<Bytes32> newCommitment) {
    return new StemNode<K, V>(location, stem, newCommitment, children);
  }

  /**
   * Find index of only non-null child if it exists.
   *
   * @return The optional index.
   */
  Optional<Integer> findOnlyChild() {
    Optional<Integer> onlyChildIndex = Optional.empty();
    for (int i = 0; i < children.size(); ++i) {
      if (!(children.get(i) instanceof NullLeafNode)) {
        if (onlyChildIndex.isPresent()) {
          return Optional.empty();
        }
        onlyChildIndex = Optional.of(i);
      }
    }
    return onlyChildIndex;
  }

  /**
   * Are all leaves null?
   *
   * @return Are all leaves null?
   */
  public boolean allLeavesAreNull() {
    // TODO: treat eventual StoredNodes as well.
    for (LeafNode<K, V> child : children) {
      if (!(child instanceof NullLeafNode)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get the RLP-encoded value of the node.
   *
   * @return The RLP-encoded value.
   */
  @Override
  public Bytes encode() {
    return Bytes.concatenate(
        Bytes.of(stem.encode()), commitment.map(x -> (Bytes) x).orElse(Bytes.EMPTY));
  }

  /**
   * Generates a string representation of the stem node and its children.
   *
   * @return A string representing the stem node and its children.
   */
  @Override
  public String print() {
    String loc = location.map(lc -> lc.toBinaryString()).orElse(".");
    final StringBuilder builder = new StringBuilder();
    builder.append(
        String.format(
            "Stem[%s]: stem[%s] %s",
            loc,
            Bytes.wrap(stem.toBytes()),
            commitment.map(x -> (Bytes) x).orElse(Bytes.EMPTY).toHexString()));
    for (int i = 0; i < maxChild(); i++) {
      final Node<K, V> child = child(i);
      if (!(child instanceof NullLeafNode)) {
        builder.append("\n").append(child.print());
      }
    }
    return builder.toString();
  }

  // Not Used for now.
  // private Bytes extractStem(final Bytes stemValue) {
  // return stemValue.slice(0, 31);
  // }

  /**
   * Dot representation of the Node.
   *
   * @param showNullNodes Should include the Null Nodes.
   * @return dot representation of the Node.
   */
  @Override
  public String toDot(Boolean showNullNodes) {
    String loc = location.map(lc -> lc.toBinaryString()).orElse("");
    StringBuilder result =
        new StringBuilder()
            .append(getName())
            .append(loc)
            .append(" [label=\"S: ")
            .append(loc)
            .append("\nStem: ")
            .append(stem.toBinaryString())
            .append("\nCommitment: ")
            .append(commitment.map(x -> (Bytes) x).orElse(Bytes.EMPTY))
            .append("\"]\n");

    for (Node<K, V> child : children) {
      String edgeString =
          getName()
              + loc
              + " -> "
              + child.getName()
              + child.location.map(lc -> lc.toBinaryString()).orElse("")
              + "\n";

      if (showNullNodes || !result.toString().contains(edgeString)) {
        result.append(edgeString);
      }
      result.append(child.toDot(showNullNodes));
    }
    return result.toString();
  }
}
