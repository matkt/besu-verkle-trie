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

public class BytesBitSequenceFactory implements BitSequenceFactory<BytesBitSequence> {
  /**
   * Default empty Sequence.
   *
   * @return Empty BitSequence.
   */
  @Override
  public BytesBitSequence empty() {
    return new BytesBitSequence(0);
  }

  /**
   * Get a BytesBitSequence from a binary string representation.
   *
   * @param bits Binary string representation.
   * @return BitSequence
   */
  @Override
  public BytesBitSequence fromBinaryString(String bits) {
    if (bits == null || !bits.matches("[01]*")) {
      throw new IllegalArgumentException(
          "Input must be a binary string (only '0' and '1' allowed)");
    }

    BytesBitSequence result = new BytesBitSequence(bits.length());
    for (int i = 0; i < bits.length(); i++) {
      result.set(i, bits.charAt(i) == '1');
    }
    return result;
  }

  /**
   * Get a BytesBitSequence from a hex string representation.
   *
   * @param hexString Hex string representation.
   * @return The BitSequence
   */
  @Override
  public BytesBitSequence fromHexString(String hexString) {
    if (hexString == null || !hexString.matches("0x[0-9A-Fa-f]*")) {
      throw new IllegalArgumentException(
          "Input must be a binary string (only '0' and '1' allowed)");
    }

    int bitLength = (hexString.length() - 2) * 4;
    BytesBitSequence result = new BytesBitSequence(bitLength);
    for (int i = 0; i < hexString.length() - 2; i++) {
      int k = Integer.parseInt(hexString.substring(i + 2, i + 3), 16);
      for (int j = 4 * i + 3; j >= 4 * i; j--) {
        result.set(j, k % 2 == 1);
        k = k >> 1;
      }
    }
    return result;
  }

  /**
   * Get a BytesBitSequence from an Integer.
   *
   * @param value Integer value.
   * @return BytesBitSequence representing value in big-endian format.
   */
  public BytesBitSequence fromByte(byte value) {
    // Should implement more efficient conversion
    BytesBitSequence result = new BytesBitSequence(8);
    result.setAll(0, value);
    return result;
  }

  /**
   * Get a BytesBitSequence from an Integer.
   *
   * @param value Integer value.
   * @return BytesBitSequence representing value in big-endian format.
   */
  @Override
  public BytesBitSequence fromInteger(int value) {
    return empty().add(value);
  }

  /**
   * Decode a BytesBitSequence from the encoded form.
   *
   * @param encoded The encoded representation of a BytesBitSequence
   * @return Decoded BytesBitSequence.
   */
  @Override
  public BytesBitSequence decode(byte[] encoded) {
    byte lastByte = encoded[encoded.length - 1];
    int encodedInt = Byte.toUnsignedInt(lastByte);

    BytesBitSequence head = new BytesBitSequence(8 * (encoded.length - 1));
    for (int i = 0; i < encoded.length - 1; i++) {
      head.setAll(8 * i, encoded[i]);
    }
    if (encodedInt == 0) {
      return head;
    }

    int power = 256;
    byte[] out = new byte[8];
    int len = 0;
    while (encodedInt > 0) {
      power /= 2;
      if (encodedInt >= power) {
        encodedInt -= power;
        out[len] = 1;
      } else {
        encodedInt -= 1;
        out[len] = 0;
      }
      len++;
    }
    byte[] tailData = new byte[len];
    System.arraycopy(out, 0, tailData, 0, len);
    BytesBitSequence tail = new BytesBitSequence(tailData);
    return head.concatenate(tail);
  }
}
