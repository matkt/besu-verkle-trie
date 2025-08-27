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
        Bytes32.fromHexString("0x0465eaac9b0028764029ece5c89c0d68f2464336f2faa877bfe30a6339f0491e");
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
        Bytes32.fromHexString("0x49b968480d7c33de088af79bcd41059ee524cfd87f656e2fd2405a68ffebeea9");
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
        Bytes32.fromHexString("0xecb8d642dea8f9e01845b43c889270e6fe4874ade0ddca9847f4edf0fe1f4cb2");
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
        Bytes32.fromHexString("0x8de3bc39cb7ba8dcf3f20be51750144fbd05aea64c5211f3030b65a888993198");
    assertThat(trie.getRootHash()).as("Retrieve root hash").isEqualByComparingTo(expectedRootHash);
  }
}
