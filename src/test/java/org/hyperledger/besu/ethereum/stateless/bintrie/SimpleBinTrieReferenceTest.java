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

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SimpleBinTrieReferenceTest {
  static BytesPackedBitSequenceFactory keyFactory;

  @BeforeAll
  static void setup() {
    keyFactory = new BytesPackedBitSequenceFactory();
  }

  @Test
  public void testOneValue() {
    SimpleBinTrie<BytesPackedBitSequence, Bytes32> trie = new SimpleBinTrie<>();
    BytesPackedBitSequence key =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000000");
    Bytes32 value =
        Bytes32.fromHexString("0x0101010101010101010101010101010101010101010101010101010101010101");
    trie.put(key, value);
    Bytes32 expectedRootHash =
        Bytes32.fromHexString("0xaab1060e04cb4f5dc6f697ae93156a95714debbf77d54238766adc5709282b6f");
    assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
  }

  @Test
  public void testTwoEntriesDifferentFirstBit() {
    SimpleBinTrie<BytesPackedBitSequence, Bytes32> trie = new SimpleBinTrie<>();
    BytesPackedBitSequence key =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000000");
    Bytes32 value =
        Bytes32.fromHexString("0x0101010101010101010101010101010101010101010101010101010101010101");
    trie.put(key, value);

    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x8000000000000000000000000000000000000000000000000000000000000000");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0202020202020202020202020202020202020202020202020202020202020202");
    trie.put(key2, value2);
    Bytes32 expectedRootHash =
        Bytes32.fromHexString("0xdfc69c94013a8b3c65395625a719a87534a7cfd38719251ad8c8ea7fe79f065e");
    assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
  }

  @Test
  public void testOneStemColocatedValue() {
    SimpleBinTrie<BytesPackedBitSequence, Bytes32> trie = new SimpleBinTrie<>();
    BytesPackedBitSequence key =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000003");
    Bytes32 value =
        Bytes32.fromHexString("0x0101010101010101010101010101010101010101010101010101010101010101");
    trie.put(key, value);

    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000004");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0202020202020202020202020202020202020202020202020202020202020202");
    trie.put(key2, value2);

    BytesPackedBitSequence key3 =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000009");
    Bytes32 value3 =
        Bytes32.fromHexString("0x0303030303030303030303030303030303030303030303030303030303030303");
    trie.put(key3, value3);

    BytesPackedBitSequence key4 =
        keyFactory.fromHexString(
            "0x00000000000000000000000000000000000000000000000000000000000000FF");
    Bytes32 value4 =
        Bytes32.fromHexString("0x0404040404040404040404040404040404040404040404040404040404040404");
    trie.put(key4, value4);
    Bytes32 expectedRootHash =
        Bytes32.fromHexString("0x95408f8e449f5745ac648bbc53fef7e46f0f486218a1d35b94b3ffcb0dfaf703");
    assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
  }

  @Test
  public void testTwoStemColocatedValue() {
    SimpleBinTrie<BytesPackedBitSequence, Bytes32> trie = new SimpleBinTrie<>();
    BytesPackedBitSequence key =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000003");
    Bytes32 value =
        Bytes32.fromHexString("0x0101010101010101010101010101010101010101010101010101010101010101");
    trie.put(key, value);

    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x0000000000000000000000000000000000000000000000000000000000000004");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0202020202020202020202020202020202020202020202020202020202020202");
    trie.put(key2, value2);

    BytesPackedBitSequence key3 =
        keyFactory.fromHexString(
            "0x8000000000000000000000000000000000000000000000000000000000000003");
    Bytes32 value3 =
        Bytes32.fromHexString("0x0101010101010101010101010101010101010101010101010101010101010101");
    trie.put(key3, value3);

    BytesPackedBitSequence key4 =
        keyFactory.fromHexString(
            "0x8000000000000000000000000000000000000000000000000000000000000004");
    Bytes32 value4 =
        Bytes32.fromHexString("0x0202020202020202020202020202020202020202020202020202020202020202");
    trie.put(key4, value4);
    Bytes32 expectedRootHash =
        Bytes32.fromHexString("0x0c383c4a5cbfc2d228924c96376029c7f07a54fb5177b5ac6657a633c422c7f5");
    assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
  }
}
