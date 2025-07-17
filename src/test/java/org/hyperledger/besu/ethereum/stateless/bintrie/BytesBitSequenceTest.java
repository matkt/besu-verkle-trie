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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

public class BytesBitSequenceTest {

  @Test
  public void testSetAndGet() {
    BytesBitSequence seq = new BytesBitSequence(3);
    seq.set(0, true);
    seq.set(1, false);
    seq.set(2, true);

    assertThat(seq.length()).isEqualTo(3);
    assertThat(seq.get(0)).isTrue();
    assertThat(seq.get(1)).isFalse();
    assertThat(seq.get(2)).isTrue();
  }

  @Test
  public void testFromBinaryString() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("10101");
    assertThat(seq.length()).isEqualTo(5);
    assertThat(seq.get(0)).isTrue();
    assertThat(seq.get(1)).isFalse();
    assertThat(seq.get(2)).isTrue();
    assertThat(seq.get(3)).isFalse();
    assertThat(seq.get(4)).isTrue();
  }

  @Test
  public void testLongFromBinaryString() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("10101111001001110");
    assertThat(seq.length()).isEqualTo(17);
    assertThat(seq.get(0)).isTrue();
    assertThat(seq.get(-1)).isFalse();
    assertThat(seq.get(16)).isFalse();
  }

  @Test
  public void testToInt() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("1011");
    assertThat(seq.toInt()).isEqualTo(11);
    BytesBitSequence seq2 = BytesBitSequence.fromBinaryString("1".repeat(32));
    assertThat(seq2.toInt()).isEqualTo(-1);
  }

  @Test
  public void testToIntOverflow() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("1".repeat(33));
    assertThatThrownBy(seq::toInt).isInstanceOf(ArithmeticException.class);
  }

  @Test
  public void testAddBit() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("101");
    BytesBitSequence seq2 = seq.add(true);
    assertThat(seq2.toBinaryString()).isEqualTo("1011");
  }

  @Test
  public void testSlice() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("1101011");
    BytesBitSequence slice = seq.slice(2, 6); // 0101
    assertThat(slice.toBinaryString()).isEqualTo("0101");
  }

  @Test
  public void testSliceAlignedFastPath() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("1111000");
    BytesBitSequence slice = seq.slice(0, 7);
    assertThat(slice.toBinaryString()).isEqualTo("1111000");
    BytesBitSequence slice2 = seq.slice(0);
    assertThat(slice2.toBinaryString()).isEqualTo("1111000");
  }

  @Test
  public void testCommonPrefix() {
    BytesBitSequence seq = BytesBitSequence.fromBinaryString("101100");
    BytesBitSequence other = BytesBitSequence.fromBinaryString("10100");
    BytesBitSequence prefix = seq.commonPrefix(other);
    assertThat(prefix.toBinaryString()).isEqualTo("101");
  }

  @Test
  public void testEqualsAndHashCode() {
    BytesBitSequence a = BytesBitSequence.fromBinaryString("1101");
    BytesBitSequence b = BytesBitSequence.fromBinaryString("1101");
    BytesBitSequence c = BytesBitSequence.fromBinaryString("1100");

    assertThat(a).isEqualTo(b);
    assertThat(a).isNotEqualTo(c);
    assertThat(a).hasSameHashCodeAs(b);
  }

  @Test
  public void testCompareTo() {
    BytesBitSequence a = BytesBitSequence.fromBinaryString("101");
    BytesBitSequence b = BytesBitSequence.fromBinaryString("110");
    BytesBitSequence c = BytesBitSequence.fromBinaryString("101");

    assertThat(a.compareTo(b) < 0).isTrue();
    assertThat(a.compareTo(c)).isEqualTo(0);
    assertThat(b.compareTo(a) > 0).isTrue();
  }

  @Test
  public void testLexicographicOrder() {
    BytesBitSequence previous = BytesBitSequence.empty().add(0, 7);
    for (int i = 1; i < 128; i++) {
      BytesBitSequence current = BytesBitSequence.empty().add(i, 7);
      assertThat(previous.compareTo(current) < 0)
          .as(
              String.format(
                  "Test LexOrder %s < %s", previous.toBinaryString(), current.toBinaryString()))
          .isTrue();
      byte[] prev = previous.encode();
      byte[] curr = current.encode();
      assertThat(prev[0] < (curr[0] & 0xFF))
          .as(String.format("Test Encoded LexOrder %s < %s", prev[0], curr[0]))
          .isTrue();
      previous = current;
    }
  }

  @Test
  public void testEncodeEmpty() {
    BytesBitSequence a = new BytesBitSequence(0);
    byte[] encoded = a.encode();
    assertThat(encoded.length).isEqualTo(0);
  }

  @Test
  public void testEncodeDecodeOneByte() {
    BytesBitSequence a = BytesBitSequence.fromBinaryString("1101");
    byte[] encoded = a.encode();
    assertThat(encoded[0]).isEqualTo((byte) Integer.parseInt("11010001", 2));
    BytesBitSequence b = BytesBitSequence.decode(encoded);
    assertThat(a).isEqualTo(b);
  }

  @Test
  public void testEncodeDecodeMultiBytes() {
    BytesBitSequence a = BytesBitSequence.fromBinaryString("1101001001");
    byte[] encoded = a.encode();
    assertThat(encoded[0]).as("Encoded 1st Byte").isEqualTo((byte) Integer.parseInt("11010010", 2));
    assertThat(encoded[1]).as("Encoded 2nd Byte").isEqualTo((byte) Integer.parseInt("01000001", 2));
    BytesBitSequence b = BytesBitSequence.decode(encoded);
    assertThat(a).as("There and back").isEqualTo(b);
  }

  @Test
  public void testEncodeDecodeMultiBytesFullyPacked() {
    BytesBitSequence a = BytesBitSequence.fromBinaryString("11111110000000");
    byte[] encoded = a.encode();
    assertThat(encoded.length).isEqualTo(2);
    assertThat(encoded[0]).as("Encoded 1st Byte").isEqualTo((byte) Integer.parseInt("11111110", 2));
    assertThat(encoded[1]).as("Encoded 2nd Byte").isEqualTo((byte) Integer.parseInt("00000110", 2));
    BytesBitSequence b = BytesBitSequence.decode(encoded);
    assertThat(a).as("There and back").isEqualTo(b);
  }
}
