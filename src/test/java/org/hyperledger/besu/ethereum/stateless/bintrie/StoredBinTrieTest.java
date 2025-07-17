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

import org.hyperledger.besu.ethereum.stateless.bintrie.factory.StoredNodeFactory;
import org.hyperledger.besu.ethereum.stateless.bintrie.factory.StoredValueNodeFactory;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.function.Function;

public class StoredBinTrieTest {
  BytesPackedBitSequenceFactory keyFactory;
  StoredNodeFactory<BytesPackedBitSequence, Bytes32> nodeFactory;
  NodeUpdaterMock nodeUpdater;
  NodeLoaderMock nodeLoader;
  Function<Bytes, Bytes32> valueDeserializer;

  @BeforeEach
  void setup() {
    keyFactory = new BytesPackedBitSequenceFactory();
    nodeUpdater = new NodeUpdaterMock();
    nodeLoader = new NodeLoaderMock(nodeUpdater.storage);
    valueDeserializer = x -> (Bytes32) x;
    nodeFactory =
        new StoredNodeFactory<BytesPackedBitSequence, Bytes32>(nodeLoader, keyFactory, valueDeserializer);
  }

  @Test
  public void testEmptyTrie() {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).isEqualTo(trie.getRootHash());
  }

  @Test
  public void testOneValue() {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    trie.put(key, value);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).as("Root Hash").isEqualTo(trie.getRootHash());
    storedTrie.get(key);
    assertThat(storedTrie.get(key).orElse(null)).as("Retrieved value").isEqualTo(value);
  }

  @Test
  public void testDeleteAlreadyDeletedValue() {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    trie.put(key, value);
    trie.remove(key);
    trie.remove(key);
    assertThat(trie.getRootHash()).isEqualTo(Bytes32.ZERO);
  }

  @Test
  public void testTwoValuesAtSameStem() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key1 =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value1 =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddee00");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
    trie.put(key1, value1);
    trie.put(key2, value2);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).isEqualTo(trie.getRootHash());
    assertThat(storedTrie.get(key1).orElse(null)).isEqualTo(value1);
    assertThat(storedTrie.get(key2).orElse(null)).isEqualTo(value2);
  }

  @Test
  public void testTwoValuesAtDifferentIndex() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key1 =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value1 =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0xff112233445566778899aabbccddeeff00112233445566778899aabbccddee00");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
    trie.put(key1, value1);
    trie.put(key2, value2);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).isEqualTo(trie.getRootHash());
    assertThat(storedTrie.get(key1).orElse(null)).isEqualTo(value1);
    assertThat(storedTrie.get(key2).orElse(null)).isEqualTo(value2);
  }

  @Test
  public void testTwoValuesWithDivergentStemsAtDepth2() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key1 =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value1 =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0100000000000000000000000000000000000000000000000000000000000000");
    trie.put(key1, value1);
    trie.put(key2, value2);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).isEqualTo(trie.getRootHash());
    assertThat(storedTrie.get(key1).orElse(null)).isEqualTo(value1);
    assertThat(storedTrie.get(key2).orElse(null)).isEqualTo(value2);
  }

  @Test
  public void testDeleteThreeValues() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key1 =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value1 =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0200000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key3 =
        keyFactory.fromHexString(
            "0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddff");
    Bytes32 value3 =
        Bytes32.fromHexString("0x0300000000000000000000000000000000000000000000000000000000000000");
    trie.put(key1, value1);
    trie.put(key2, value2);
    trie.put(key3, value3);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).isEqualTo(trie.getRootHash());
    assertThat(storedTrie.get(key1).orElse(null)).isEqualTo(value1);
    assertThat(storedTrie.get(key2).orElse(null)).isEqualTo(value2);
    assertThat(storedTrie.get(key3).orElse(null)).isEqualTo(value3);
  }

  @Test
  public void testDeleteThreeValuesWithFlattening() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    BytesPackedBitSequence key1 =
        keyFactory.fromHexString(
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    Bytes32 value1 =
        Bytes32.fromHexString("0x1000000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
    Bytes32 value2 =
        Bytes32.fromHexString("0x0200000000000000000000000000000000000000000000000000000000000000");
    BytesPackedBitSequence key3 =
        keyFactory.fromHexString(
            "0x00ff112233445566778899aabbccddeeff00112233445566778899aabbccddff");
    Bytes32 value3 =
        Bytes32.fromHexString("0x0300000000000000000000000000000000000000000000000000000000000000");
    trie.put(key1, value1);
    trie.put(key2, value2);
    trie.put(key3, value3);
    trie.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> storedTrie = new StoredBinTrie<>(nodeFactory);
    assertThat(storedTrie.getRootHash()).isEqualTo(trie.getRootHash());
    assertThat(storedTrie.get(key1).orElse(null)).isEqualTo(value1);
    assertThat(storedTrie.get(key2).orElse(null)).isEqualTo(value2);
    assertThat(storedTrie.get(key3).orElse(null)).isEqualTo(value3);
  }

  @Test
  public void testDeleteManyValuesWithDivergentStemsAtDepth2() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);

    assertThat(trie.getRootHash()).isEqualTo(Bytes32.ZERO);
    BytesPackedBitSequence key0 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45641");
    Bytes32 value0 =
        Bytes32.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001");
    BytesPackedBitSequence key1 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45601");
    Bytes32 value1 =
        Bytes32.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001");
    BytesPackedBitSequence key2 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45602");
    Bytes32 value2 = Bytes32.fromHexString("0x01");
    BytesPackedBitSequence key3 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45600");
    Bytes32 value3 = Bytes32.fromHexString("0x00");
    BytesPackedBitSequence key4 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45603");
    Bytes32 value4 =
        Bytes32.fromHexString("0xf84a97f1f0a956e738abd85c2e0a5026f8874e3ec09c8f012159dfeeaab2b156");
    BytesPackedBitSequence key5 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45604");
    Bytes32 value5 = Bytes32.fromHexString("0x03");
    BytesPackedBitSequence key6 =
        keyFactory.fromHexString(
            "0x1e4abaeaa58259f4784e086ddbaa74a9d3975efb2e4380595f0eed5692c45680");
    Bytes32 value6 =
        Bytes32.fromHexString("0x0000010200000000000000000000000000000000000000000000000000000000");
    trie.put(key0, value0);
    trie.put(key1, value1);
    trie.put(key2, value2);
    trie.put(key3, value3);
    trie.put(key4, value4);
    trie.put(key5, value5);
    trie.put(key6, value6);

    trie.commit(nodeUpdater);
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie2 = new StoredBinTrie<>(nodeFactory);
    assertThat(trie2.getRootHash()).isEqualTo(trie.getRootHash());
    trie2.remove(key0);
    trie2.remove(key4);
    trie2.remove(key5);
    trie2.remove(key6);
    trie2.remove(key3);
    trie2.remove(key1);
    trie2.remove(key2);
    assertThat(trie2.getRootHash()).isEqualTo(Bytes32.ZERO);
  }

  @Test
  public void testAddAndRemoveKeysWithMultipleTreeReloads() throws Exception {
    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie = new StoredBinTrie<>(nodeFactory);
    trie.put(
        keyFactory.fromHexString(
            "0x1123356d04d4bd662ba38c44cbd79d4108521284d80327fa533e0baab1af9fff"),
        Bytes32.fromHexString(
            "0x4ff50e1454f9a9f56871911ad5b785b7f9966cce3cb12eb0e989332ae2279213"));
    trie.commit(nodeUpdater);
    Bytes32 expectedRootHash = trie.getRootHash();

    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie2 = new StoredBinTrie<>(nodeFactory);
    trie2.put(
        keyFactory.fromHexString(
            "0x117b67dd491b9e11d9cde84ef3c02f11ddee9e18284969dc7d496d43c300e500"),
        Bytes32.fromHexString(
            "0x4ff50e1454f9a9f56871911ad5b785b7f9966cce3cb12eb0e989332ae2279213"));

    trie2.commit(nodeUpdater);

    StoredBinTrie<BytesPackedBitSequence, Bytes32> trie3 = new StoredBinTrie<>(nodeFactory);

    trie3.remove(
        keyFactory.fromHexString(
            "0x117b67dd491b9e11d9cde84ef3c02f11ddee9e18284969dc7d496d43c300e500"));
    trie3.commit(nodeUpdater);

    assertThat(trie3.getRootHash()).isEqualTo(expectedRootHash);
  }
}
