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
package org.hyperledger.besu.ethereum.stateless.bintrie.hasher;

import org.hyperledger.besu.ethereum.stateless.bintrie.node.Node;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.SHA256Digest;

/** Class for Hashing values. */
public class Hasher {

  public Hasher() {}

  public Bytes32 hash(final Bytes32 value) {
    final SHA256Digest digest = getDigest();
    digest.update(value.toArrayUnsafe(), 0, value.size());
    final byte[] dig = new byte[digest.getDigestSize()];
    digest.doFinal(dig, 0);
    return Bytes32.wrap(dig);
  }

  public Bytes32 hash(final Optional<Bytes32> left, final Optional<Bytes32> right) {
    Bytes32 leftValue = left.orElse(Node.EMPTY_COMMITMENT);
    Bytes32 rightValue = right.orElse(Node.EMPTY_COMMITMENT);
    return hash(leftValue, rightValue);
  }

  public Bytes32 hash(final Bytes32 leftValue, final Bytes32 rightValue) {
    if (leftValue == Node.EMPTY_COMMITMENT && rightValue == Node.EMPTY_COMMITMENT) {
      return Node.EMPTY_COMMITMENT;
    }
    final SHA256Digest digest = getDigest();
    final byte[] rawDigest = new byte[digest.getDigestSize()];
    digest.reset();
    digest.update(leftValue.toArray(), 0, leftValue.size());
    digest.update(rightValue.toArray(), 0, rightValue.size());
    digest.doFinal(rawDigest, 0);
    Bytes32 result = (Bytes32) Bytes.of(rawDigest);
    digest.reset();
    return result;
  }

  private SHA256Digest getDigest() {
    return new SHA256Digest();
  }
}
