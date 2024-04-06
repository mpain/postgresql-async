/*
 * Copyright 2021 Arman Bilge
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright 2008-2018 MongoDB, Inc.
 * Copyright 2017 Tom Bentley
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.mauricio.async.db.postgresql.sasl

import java.nio.CharBuffer
import java.text.Normalizer

/**
 * https://github.com/mongodb/mongosql-auth-java/blob/master/src/main/java/org/mongodb/mongosql/auth/plugin/SaslPrep.java
 */
object SaslPrep {

  /**
   * Return the {@code SASLPrep}-canonicalised version of the given {@code str} for use as a
   * query string. This implements the {@code SASLPrep} algorithm defined in <a
   * href="https://tools.ietf.org/html/rfc4013">RFC 4013</a>.
   *
   * @param str
   *   The string to canonicalise.
   * @return
   *   The canonicalised string.
   * @see
   *   <a href="https://tools.ietf.org/html/rfc3454#section-7">RFC 3454, Section 7</a> for
   *   discussion of what a query string is.
   */
  def saslPrepQuery(str: String): String = {
    saslPrep(str, true)
  }

  /**
   * Return the {@code SASLPrep}-canonicalised version of the given {@code str} for use as a
   * stored string. This implements the {@code SASLPrep} algorithm defined in <a
   * href="https://tools.ietf.org/html/rfc4013">RFC 4013</a>.
   *
   * @param str
   *   The string to canonicalise.
   * @return
   *   The canonicalised string.
   * @see
   *   <a href="https://tools.ietf.org/html/rfc3454#section-7">RFC 3454, Section 7</a> for
   *   discussion of what a stored string is.
   */
  def saslPrepStored(str: String): String = {
    saslPrep(str, false)
  }

  private[this] def saslPrep(str: String, allowUnassigned: Boolean) = {
    val chars = str.toCharArray()

    // 1. Map

    // non-ASCII space chars mapped to space
    for (i <- str.indices) {
      val ch = str.charAt(i)
      if (nonAsciiSpace(ch)) {
        chars(i) = ' '
      }
    }

    var length = 0
    for (i <- str.indices) {
      val ch = chars(i)
      if (!mappedToNothing(ch)) {
        chars(length) = ch
        length += 1
      }
    }

    // 2. Normalize
    val normalized =
      Normalizer.normalize(CharBuffer.wrap(chars, 0, length), Normalizer.Form.NFKC)

    var containsRandALCat = false
    var containsLCat = false
    var initialRandALCat = false
    var i = 0
    while (i < normalized.length()) {
      val codepoint = normalized.codePointAt(i)
      // 3. Prohibit
      if (prohibited(codepoint)) {
        throw new IllegalArgumentException(
          "Prohibited character at position " + i
        )
      }

      // 4. Check bidi
      val isRandALcat = bidiROrAL(codepoint)
      containsRandALCat |= isRandALcat
      containsLCat |= bidiL(codepoint)

      initialRandALCat |= i == 0 && isRandALcat
      if (!allowUnassigned && !Character.isDefined(codepoint)) {
        throw new IllegalArgumentException(
          "Character at position " + i + " is unassigned"
        )
      }
      i += Character.charCount(codepoint)

      if (initialRandALCat && i >= normalized.length() && !isRandALcat) {
        throw new IllegalArgumentException(
          "First character is RandALCat, but last character is not"
        )
      }
    }
    if (containsRandALCat && containsLCat) {
      throw new IllegalArgumentException(
        "Contains both RandALCat characters and LCat characters"
      )
    }

    normalized
  }

  /**
   * Return true if the given {@code codepoint} is a prohibited character as defined by <a
   * href="https://tools.ietf.org/html/rfc4013#section-2.3">RFC 4013, Section 2.3</a>.
   */
  private[sasl] def prohibited(codepoint: Int) = {
    nonAsciiSpace(codepoint.toChar) ||
      asciiControl(codepoint.toChar) ||
      nonAsciiControl(codepoint) ||
      privateUse(codepoint) ||
      nonCharacterCodePoint(codepoint) ||
      surrogateCodePoint(codepoint) ||
      inappropriateForPlainText(codepoint) ||
      inappropriateForCanonical(codepoint) ||
      changeDisplayProperties(codepoint) ||
      tagging(codepoint)
  }

  /**
   * Return true if the given {@code codepoint} is a tagging character as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.9">RFC 3454, Appendix C.9</a>.
   */
  private def tagging(codepoint: Int) = {
    codepoint == 0xe0001 ||
      0xe0020 <= codepoint && codepoint <= 0xe007f
  }

  /**
   * Return true if the given {@code codepoint} is change display properties or deprecated
   * characters as defined by <a href="https://tools.ietf.org/html/rfc3454#appendix-C.8">RFC
   * 3454, Appendix C.8</a>.
   */
  private[this] def changeDisplayProperties(codepoint: Int) = {
    codepoint == 0x0340 ||
      codepoint == 0x0341 ||
      codepoint == 0x200e ||
      codepoint == 0x200f ||
      codepoint == 0x202a ||
      codepoint == 0x202b ||
      codepoint == 0x202c ||
      codepoint == 0x202d ||
      codepoint == 0x202e ||
      codepoint == 0x206a ||
      codepoint == 0x206b ||
      codepoint == 0x206c ||
      codepoint == 0x206d ||
      codepoint == 0x206e ||
      codepoint == 0x206f
  }

  /**
   * Return true if the given {@code codepoint} is inappropriate for canonical representation
   * characters as defined by <a href="https://tools.ietf.org/html/rfc3454#appendix-C.7">RFC
   * 3454, Appendix C.7</a>.
   */
  private[this] def inappropriateForCanonical(codepoint: Int) = {
    0x2ff0 <= codepoint && codepoint <= 0x2ffb
  }

  /**
   * Return true if the given {@code codepoint} is inappropriate for plain text characters as
   * defined by <a href="https://tools.ietf.org/html/rfc3454#appendix-C.6">RFC 3454, Appendix
   * C.6</a>.
   */
  private[this] def inappropriateForPlainText(codepoint: Int) = {
    codepoint == 0xfff9 ||
      codepoint == 0xfffa ||
      codepoint == 0xfffb ||
      codepoint == 0xfffc ||
      codepoint == 0xfffd
  }

  /**
   * Return true if the given {@code codepoint} is a surrogate code point as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.5">RFC 3454, Appendix C.5</a>.
   */
  private[this] def surrogateCodePoint(codepoint: Int) = {
    0xd800 <= codepoint && codepoint <= 0xdfff
  }

  /**
   * Return true if the given {@code codepoint} is a non-character code point as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.4">RFC 3454, Appendix C.4</a>.
   */
  private[this] def nonCharacterCodePoint(codepoint: Int) = {
    0xfdd0 <= codepoint && codepoint <= 0xfdef ||
      0xfffe <= codepoint && codepoint <= 0xffff ||
      0x1fffe <= codepoint && codepoint <= 0x1ffff ||
      0x2fffe <= codepoint && codepoint <= 0x2ffff ||
      0x3fffe <= codepoint && codepoint <= 0x3ffff ||
      0x4fffe <= codepoint && codepoint <= 0x4ffff ||
      0x5fffe <= codepoint && codepoint <= 0x5ffff ||
      0x6fffe <= codepoint && codepoint <= 0x6ffff ||
      0x7fffe <= codepoint && codepoint <= 0x7ffff ||
      0x8fffe <= codepoint && codepoint <= 0x8ffff ||
      0x9fffe <= codepoint && codepoint <= 0x9ffff ||
      0xafffe <= codepoint && codepoint <= 0xaffff ||
      0xbfffe <= codepoint && codepoint <= 0xbffff ||
      0xcfffe <= codepoint && codepoint <= 0xcffff ||
      0xdfffe <= codepoint && codepoint <= 0xdffff ||
      0xefffe <= codepoint && codepoint <= 0xeffff ||
      0xffffe <= codepoint && codepoint <= 0xfffff ||
      0x10fffe <= codepoint && codepoint <= 0x10ffff
  }

  /**
   * Return true if the given {@code codepoint} is a private use character as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.3">RFC 3454, Appendix C.3</a>.
   */
  private[this] def privateUse(codepoint: Int) = {
    0xe000 <= codepoint && codepoint <= 0xf8ff ||
      0xf000 <= codepoint && codepoint <= 0xffffd ||
      0x100000 <= codepoint && codepoint <= 0x10fffd
  }

  /**
   * Return true if the given {@code ch} is a non-ASCII control character as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.2.2">RFC 3454, Appendix C.2.2</a>.
   */
  private[this] def nonAsciiControl(codepoint: Int) = {
    0x0080 <= codepoint && codepoint <= 0x009f ||
      codepoint == 0x06dd ||
      codepoint == 0x070f ||
      codepoint == 0x180e ||
      codepoint == 0x200c ||
      codepoint == 0x200d ||
      codepoint == 0x2028 ||
      codepoint == 0x2029 ||
      codepoint == 0x2060 ||
      codepoint == 0x2061 ||
      codepoint == 0x2062 ||
      codepoint == 0x2063 ||
      0x206a <= codepoint && codepoint <= 0x206f ||
      codepoint == 0xfeff ||
      0xfff9 <= codepoint && codepoint <= 0xfffc ||
      0x1d173 <= codepoint && codepoint <= 0x1d17a
  }

  /**
   * Return true if the given {@code ch} is an ASCII control character as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.2.1">RFC 3454, Appendix C.2.1</a>.
   */
  private[this] def asciiControl(ch: Char) = {
    ch <= '\u001F' ||
      ch == '\u007F'
  }

  /**
   * Return true if the given {@code ch} is a non-ASCII space character as defined by <a
   * href="https://tools.ietf.org/html/rfc3454#appendix-C.1.2">RFC 3454, Appendix C.1.2</a>.
   */
  private[this] def nonAsciiSpace(ch: Char) = {
    ch == '\u00A0' ||
      ch == '\u1680' ||
      '\u2000' <= ch && ch <= '\u200B' ||
      ch == '\u202F' ||
      ch == '\u205F' ||
      ch == '\u3000'
  }

  /**
   * Return true if the given {@code ch} is a "commonly mapped to nothing" character as defined
   * by <a href="https://tools.ietf.org/html/rfc3454#appendix-B.1">RFC 3454, Appendix B.1</a>.
   */
  private[this] def mappedToNothing(ch: Char) = {
    ch == '\u00AD' ||
      ch == '\u034F' ||
      ch == '\u1806' ||
      ch == '\u180B' ||
      ch == '\u180C' ||
      ch == '\u180D' ||
      ch == '\u200B' ||
      ch == '\u200C' ||
      ch == '\u200D' ||
      ch == '\u2060' ||
      '\uFE00' <= ch && ch <= '\uFE0F' ||
      ch == '\uFEFF'
  }

  /**
   * https://datatracker.ietf.org/doc/html/rfc3454#appendix-D.1
   */
  private[this] def bidiROrAL(codepoint: Int) = {
    codepoint == 0x05be ||
      codepoint == 0x05c0 ||
      codepoint == 0x05c3 ||
      0x05d0 <= codepoint && codepoint <= 0x05ea ||
      0x05f0 <= codepoint && codepoint <= 0x05f4 ||
      codepoint == 0x061b ||
      codepoint == 0x061f ||
      0x0621 <= codepoint && codepoint <= 0x063a ||
      0x0640 <= codepoint && codepoint <= 0x064a ||
      0x066d <= codepoint && codepoint <= 0x066f ||
      0x0671 <= codepoint && codepoint <= 0x06d5 ||
      codepoint == 0x06dd ||
      0x06e5 <= codepoint && codepoint <= 0x06e6 ||
      0x06fa <= codepoint && codepoint <= 0x06fe ||
      0x0700 <= codepoint && codepoint <= 0x070d ||
      codepoint == 0x0710 ||
      0x0712 <= codepoint && codepoint <= 0x072c ||
      0x0780 <= codepoint && codepoint <= 0x07a5 ||
      codepoint == 0x07b1 ||
      codepoint == 0x200f ||
      codepoint == 0xfb1d ||
      0xfb1f <= codepoint && codepoint <= 0xfb28 ||
      0xfb2a <= codepoint && codepoint <= 0xfb36 ||
      0xfb38 <= codepoint && codepoint <= 0xfb3c ||
      codepoint == 0xfb3e ||
      0xfb40 <= codepoint && codepoint <= 0xfb41 ||
      0xfb43 <= codepoint && codepoint <= 0xfb44 ||
      0xfb46 <= codepoint && codepoint <= 0xfbb1 ||
      0xfbd3 <= codepoint && codepoint <= 0xfd3d ||
      0xfd50 <= codepoint && codepoint <= 0xfd8f ||
      0xfd92 <= codepoint && codepoint <= 0xfdc7 ||
      0xfdf0 <= codepoint && codepoint <= 0xfdfc ||
      0xfe70 <= codepoint && codepoint <= 0xfe74 ||
      0xfe76 <= codepoint && codepoint <= 0xfefc
  }

  /**
   * https://datatracker.ietf.org/doc/html/rfc3454#appendix-D.2
   */
  private[this] def bidiL(codepoint: Int) = {
    0x0041 <= codepoint && codepoint <= 0x005a ||
      0x0061 <= codepoint && codepoint <= 0x007a ||
      codepoint == 0x00aa ||
      codepoint == 0x00b5 ||
      codepoint == 0x00ba ||
      0x00c0 <= codepoint && codepoint <= 0x00d6 ||
      0x00d8 <= codepoint && codepoint <= 0x00f6 ||
      0x00f8 <= codepoint && codepoint <= 0x0220 ||
      0x0222 <= codepoint && codepoint <= 0x0233 ||
      0x0250 <= codepoint && codepoint <= 0x02ad ||
      0x02b0 <= codepoint && codepoint <= 0x02b8 ||
      0x02bb <= codepoint && codepoint <= 0x02c1 ||
      0x02d0 <= codepoint && codepoint <= 0x02d1 ||
      0x02e0 <= codepoint && codepoint <= 0x02e4 ||
      codepoint == 0x02ee ||
      codepoint == 0x037a ||
      codepoint == 0x0386 ||
      0x0388 <= codepoint && codepoint <= 0x038a ||
      codepoint == 0x038c ||
      0x038e <= codepoint && codepoint <= 0x03a1 ||
      0x03a3 <= codepoint && codepoint <= 0x03ce ||
      0x03d0 <= codepoint && codepoint <= 0x03f5 ||
      0x0400 <= codepoint && codepoint <= 0x0482 ||
      0x048a <= codepoint && codepoint <= 0x04ce ||
      0x04d0 <= codepoint && codepoint <= 0x04f5 ||
      0x04f8 <= codepoint && codepoint <= 0x04f9 ||
      0x0500 <= codepoint && codepoint <= 0x050f ||
      0x0531 <= codepoint && codepoint <= 0x0556 ||
      0x0559 <= codepoint && codepoint <= 0x055f ||
      0x0561 <= codepoint && codepoint <= 0x0587 ||
      codepoint == 0x0589 ||
      codepoint == 0x0903 ||
      0x0905 <= codepoint && codepoint <= 0x0939 ||
      0x093d <= codepoint && codepoint <= 0x0940 ||
      0x0949 <= codepoint && codepoint <= 0x094c ||
      codepoint == 0x0950 ||
      0x0958 <= codepoint && codepoint <= 0x0961 ||
      0x0964 <= codepoint && codepoint <= 0x0970 ||
      0x0982 <= codepoint && codepoint <= 0x0983 ||
      0x0985 <= codepoint && codepoint <= 0x098c ||
      0x098f <= codepoint && codepoint <= 0x0990 ||
      0x0993 <= codepoint && codepoint <= 0x09a8 ||
      0x09aa <= codepoint && codepoint <= 0x09b0 ||
      codepoint == 0x09b2 ||
      0x09b6 <= codepoint && codepoint <= 0x09b9 ||
      0x09be <= codepoint && codepoint <= 0x09c0 ||
      0x09c7 <= codepoint && codepoint <= 0x09c8 ||
      0x09cb <= codepoint && codepoint <= 0x09cc ||
      codepoint == 0x09d7 ||
      0x09dc <= codepoint && codepoint <= 0x09dd ||
      0x09df <= codepoint && codepoint <= 0x09e1 ||
      0x09e6 <= codepoint && codepoint <= 0x09f1 ||
      0x09f4 <= codepoint && codepoint <= 0x09fa ||
      0x0a05 <= codepoint && codepoint <= 0x0a0a ||
      0x0a0f <= codepoint && codepoint <= 0x0a10 ||
      0x0a13 <= codepoint && codepoint <= 0x0a28 ||
      0x0a2a <= codepoint && codepoint <= 0x0a30 ||
      0x0a32 <= codepoint && codepoint <= 0x0a33 ||
      0x0a35 <= codepoint && codepoint <= 0x0a36 ||
      0x0a38 <= codepoint && codepoint <= 0x0a39 ||
      0x0a3e <= codepoint && codepoint <= 0x0a40 ||
      0x0a59 <= codepoint && codepoint <= 0x0a5c ||
      codepoint == 0x0a5e ||
      0x0a66 <= codepoint && codepoint <= 0x0a6f ||
      0x0a72 <= codepoint && codepoint <= 0x0a74 ||
      codepoint == 0x0a83 ||
      0x0a85 <= codepoint && codepoint <= 0x0a8b ||
      codepoint == 0x0a8d ||
      0x0a8f <= codepoint && codepoint <= 0x0a91 ||
      0x0a93 <= codepoint && codepoint <= 0x0aa8 ||
      0x0aaa <= codepoint && codepoint <= 0x0ab0 ||
      0x0ab2 <= codepoint && codepoint <= 0x0ab3 ||
      0x0ab5 <= codepoint && codepoint <= 0x0ab9 ||
      0x0abd <= codepoint && codepoint <= 0x0ac0 ||
      codepoint == 0x0ac9 ||
      0x0acb <= codepoint && codepoint <= 0x0acc ||
      codepoint == 0x0ad0 ||
      codepoint == 0x0ae0 ||
      0x0ae6 <= codepoint && codepoint <= 0x0aef ||
      0x0b02 <= codepoint && codepoint <= 0x0b03 ||
      0x0b05 <= codepoint && codepoint <= 0x0b0c ||
      0x0b0f <= codepoint && codepoint <= 0x0b10 ||
      0x0b13 <= codepoint && codepoint <= 0x0b28 ||
      0x0b2a <= codepoint && codepoint <= 0x0b30 ||
      0x0b32 <= codepoint && codepoint <= 0x0b33 ||
      0x0b36 <= codepoint && codepoint <= 0x0b39 ||
      0x0b3d <= codepoint && codepoint <= 0x0b3e ||
      codepoint == 0x0b40 ||
      0x0b47 <= codepoint && codepoint <= 0x0b48 ||
      0x0b4b <= codepoint && codepoint <= 0x0b4c ||
      codepoint == 0x0b57 ||
      0x0b5c <= codepoint && codepoint <= 0x0b5d ||
      0x0b5f <= codepoint && codepoint <= 0x0b61 ||
      0x0b66 <= codepoint && codepoint <= 0x0b70 ||
      codepoint == 0x0b83 ||
      0x0b85 <= codepoint && codepoint <= 0x0b8a ||
      0x0b8e <= codepoint && codepoint <= 0x0b90 ||
      0x0b92 <= codepoint && codepoint <= 0x0b95 ||
      0x0b99 <= codepoint && codepoint <= 0x0b9a ||
      codepoint == 0x0b9c ||
      0x0b9e <= codepoint && codepoint <= 0x0b9f ||
      0x0ba3 <= codepoint && codepoint <= 0x0ba4 ||
      0x0ba8 <= codepoint && codepoint <= 0x0baa ||
      0x0bae <= codepoint && codepoint <= 0x0bb5 ||
      0x0bb7 <= codepoint && codepoint <= 0x0bb9 ||
      0x0bbe <= codepoint && codepoint <= 0x0bbf ||
      0x0bc1 <= codepoint && codepoint <= 0x0bc2 ||
      0x0bc6 <= codepoint && codepoint <= 0x0bc8 ||
      0x0bca <= codepoint && codepoint <= 0x0bcc ||
      codepoint == 0x0bd7 ||
      0x0be7 <= codepoint && codepoint <= 0x0bf2 ||
      0x0c01 <= codepoint && codepoint <= 0x0c03 ||
      0x0c05 <= codepoint && codepoint <= 0x0c0c ||
      0x0c0e <= codepoint && codepoint <= 0x0c10 ||
      0x0c12 <= codepoint && codepoint <= 0x0c28 ||
      0x0c2a <= codepoint && codepoint <= 0x0c33 ||
      0x0c35 <= codepoint && codepoint <= 0x0c39 ||
      0x0c41 <= codepoint && codepoint <= 0x0c44 ||
      0x0c60 <= codepoint && codepoint <= 0x0c61 ||
      0x0c66 <= codepoint && codepoint <= 0x0c6f ||
      0x0c82 <= codepoint && codepoint <= 0x0c83 ||
      0x0c85 <= codepoint && codepoint <= 0x0c8c ||
      0x0c8e <= codepoint && codepoint <= 0x0c90 ||
      0x0c92 <= codepoint && codepoint <= 0x0ca8 ||
      0x0caa <= codepoint && codepoint <= 0x0cb3 ||
      0x0cb5 <= codepoint && codepoint <= 0x0cb9 ||
      codepoint == 0x0cbe ||
      0x0cc0 <= codepoint && codepoint <= 0x0cc4 ||
      0x0cc7 <= codepoint && codepoint <= 0x0cc8 ||
      0x0cca <= codepoint && codepoint <= 0x0ccb ||
      0x0cd5 <= codepoint && codepoint <= 0x0cd6 ||
      codepoint == 0x0cde ||
      0x0ce0 <= codepoint && codepoint <= 0x0ce1 ||
      0x0ce6 <= codepoint && codepoint <= 0x0cef ||
      0x0d02 <= codepoint && codepoint <= 0x0d03 ||
      0x0d05 <= codepoint && codepoint <= 0x0d0c ||
      0x0d0e <= codepoint && codepoint <= 0x0d10 ||
      0x0d12 <= codepoint && codepoint <= 0x0d28 ||
      0x0d2a <= codepoint && codepoint <= 0x0d39 ||
      0x0d3e <= codepoint && codepoint <= 0x0d40 ||
      0x0d46 <= codepoint && codepoint <= 0x0d48 ||
      0x0d4a <= codepoint && codepoint <= 0x0d4c ||
      codepoint == 0x0d57 ||
      0x0d60 <= codepoint && codepoint <= 0x0d61 ||
      0x0d66 <= codepoint && codepoint <= 0x0d6f ||
      0x0d82 <= codepoint && codepoint <= 0x0d83 ||
      0x0d85 <= codepoint && codepoint <= 0x0d96 ||
      0x0d9a <= codepoint && codepoint <= 0x0db1 ||
      0x0db3 <= codepoint && codepoint <= 0x0dbb ||
      codepoint == 0x0dbd ||
      0x0dc0 <= codepoint && codepoint <= 0x0dc6 ||
      0x0dcf <= codepoint && codepoint <= 0x0dd1 ||
      0x0dd8 <= codepoint && codepoint <= 0x0ddf ||
      0x0df2 <= codepoint && codepoint <= 0x0df4 ||
      0x0e01 <= codepoint && codepoint <= 0x0e30 ||
      0x0e32 <= codepoint && codepoint <= 0x0e33 ||
      0x0e40 <= codepoint && codepoint <= 0x0e46 ||
      0x0e4f <= codepoint && codepoint <= 0x0e5b ||
      0x0e81 <= codepoint && codepoint <= 0x0e82 ||
      codepoint == 0x0e84 ||
      0x0e87 <= codepoint && codepoint <= 0x0e88 ||
      codepoint == 0x0e8a ||
      codepoint == 0x0e8d ||
      0x0e94 <= codepoint && codepoint <= 0x0e97 ||
      0x0e99 <= codepoint && codepoint <= 0x0e9f ||
      0x0ea1 <= codepoint && codepoint <= 0x0ea3 ||
      codepoint == 0x0ea5 ||
      codepoint == 0x0ea7 ||
      0x0eaa <= codepoint && codepoint <= 0x0eab ||
      0x0ead <= codepoint && codepoint <= 0x0eb0 ||
      0x0eb2 <= codepoint && codepoint <= 0x0eb3 ||
      codepoint == 0x0ebd ||
      0x0ec0 <= codepoint && codepoint <= 0x0ec4 ||
      codepoint == 0x0ec6 ||
      0x0ed0 <= codepoint && codepoint <= 0x0ed9 ||
      0x0edc <= codepoint && codepoint <= 0x0edd ||
      0x0f00 <= codepoint && codepoint <= 0x0f17 ||
      0x0f1a <= codepoint && codepoint <= 0x0f34 ||
      codepoint == 0x0f36 ||
      codepoint == 0x0f38 ||
      0x0f3e <= codepoint && codepoint <= 0x0f47 ||
      0x0f49 <= codepoint && codepoint <= 0x0f6a ||
      codepoint == 0x0f7f ||
      codepoint == 0x0f85 ||
      0x0f88 <= codepoint && codepoint <= 0x0f8b ||
      0x0fbe <= codepoint && codepoint <= 0x0fc5 ||
      0x0fc7 <= codepoint && codepoint <= 0x0fcc ||
      codepoint == 0x0fcf ||
      0x1000 <= codepoint && codepoint <= 0x1021 ||
      0x1023 <= codepoint && codepoint <= 0x1027 ||
      0x1029 <= codepoint && codepoint <= 0x102a ||
      codepoint == 0x102c ||
      codepoint == 0x1031 ||
      codepoint == 0x1038 ||
      0x1040 <= codepoint && codepoint <= 0x1057 ||
      0x10a0 <= codepoint && codepoint <= 0x10c5 ||
      0x10d0 <= codepoint && codepoint <= 0x10f8 ||
      codepoint == 0x10fb ||
      0x1100 <= codepoint && codepoint <= 0x1159 ||
      0x115f <= codepoint && codepoint <= 0x11a2 ||
      0x11a8 <= codepoint && codepoint <= 0x11f9 ||
      0x1200 <= codepoint && codepoint <= 0x1206 ||
      0x1208 <= codepoint && codepoint <= 0x1246 ||
      codepoint == 0x1248 ||
      0x124a <= codepoint && codepoint <= 0x124d ||
      0x1250 <= codepoint && codepoint <= 0x1256 ||
      codepoint == 0x1258 ||
      0x125a <= codepoint && codepoint <= 0x125d ||
      0x1260 <= codepoint && codepoint <= 0x1286 ||
      codepoint == 0x1288 ||
      0x128a <= codepoint && codepoint <= 0x128d ||
      0x1290 <= codepoint && codepoint <= 0x12ae ||
      codepoint == 0x12b0 ||
      0x12b2 <= codepoint && codepoint <= 0x12b5 ||
      0x12b8 <= codepoint && codepoint <= 0x12be ||
      codepoint == 0x12c0 ||
      0x12c2 <= codepoint && codepoint <= 0x12c5 ||
      0x12c8 <= codepoint && codepoint <= 0x12ce ||
      0x12d0 <= codepoint && codepoint <= 0x12d6 ||
      0x12d8 <= codepoint && codepoint <= 0x12ee ||
      0x12f0 <= codepoint && codepoint <= 0x130e ||
      codepoint == 0x1310 ||
      0x1312 <= codepoint && codepoint <= 0x1315 ||
      0x1318 <= codepoint && codepoint <= 0x131e ||
      0x1320 <= codepoint && codepoint <= 0x1346 ||
      0x1348 <= codepoint && codepoint <= 0x135a ||
      0x1361 <= codepoint && codepoint <= 0x137c ||
      0x13a0 <= codepoint && codepoint <= 0x13f4 ||
      0x1401 <= codepoint && codepoint <= 0x1676 ||
      0x1681 <= codepoint && codepoint <= 0x169a ||
      0x16a0 <= codepoint && codepoint <= 0x16f0 ||
      0x1700 <= codepoint && codepoint <= 0x170c ||
      0x170e <= codepoint && codepoint <= 0x1711 ||
      0x1720 <= codepoint && codepoint <= 0x1731 ||
      0x1735 <= codepoint && codepoint <= 0x1736 ||
      0x1740 <= codepoint && codepoint <= 0x1751 ||
      0x1760 <= codepoint && codepoint <= 0x176c ||
      0x176e <= codepoint && codepoint <= 0x1770 ||
      0x1780 <= codepoint && codepoint <= 0x17b6 ||
      0x17be <= codepoint && codepoint <= 0x17c5 ||
      0x17c7 <= codepoint && codepoint <= 0x17c8 ||
      0x17d4 <= codepoint && codepoint <= 0x17da ||
      codepoint == 0x17dc ||
      0x17e0 <= codepoint && codepoint <= 0x17e9 ||
      0x1810 <= codepoint && codepoint <= 0x1819 ||
      0x1820 <= codepoint && codepoint <= 0x1877 ||
      0x1880 <= codepoint && codepoint <= 0x18a8 ||
      0x1e00 <= codepoint && codepoint <= 0x1e9b ||
      0x1ea0 <= codepoint && codepoint <= 0x1ef9 ||
      0x1f00 <= codepoint && codepoint <= 0x1f15 ||
      0x1f18 <= codepoint && codepoint <= 0x1f1d ||
      0x1f20 <= codepoint && codepoint <= 0x1f45 ||
      0x1f48 <= codepoint && codepoint <= 0x1f4d ||
      0x1f50 <= codepoint && codepoint <= 0x1f57 ||
      codepoint == 0x1f59 ||
      codepoint == 0x1f5b ||
      codepoint == 0x1f5d ||
      0x1f5f <= codepoint && codepoint <= 0x1f7d ||
      0x1f80 <= codepoint && codepoint <= 0x1fb4 ||
      0x1fb6 <= codepoint && codepoint <= 0x1fbc ||
      codepoint == 0x1fbe ||
      0x1fc2 <= codepoint && codepoint <= 0x1fc4 ||
      0x1fc6 <= codepoint && codepoint <= 0x1fcc ||
      0x1fd0 <= codepoint && codepoint <= 0x1fd3 ||
      0x1fd6 <= codepoint && codepoint <= 0x1fdb ||
      0x1fe0 <= codepoint && codepoint <= 0x1fec ||
      0x1ff2 <= codepoint && codepoint <= 0x1ff4 ||
      0x1ff6 <= codepoint && codepoint <= 0x1ffc ||
      codepoint == 0x200e ||
      codepoint == 0x2071 ||
      codepoint == 0x207f ||
      codepoint == 0x2102 ||
      codepoint == 0x2107 ||
      0x210a <= codepoint && codepoint <= 0x2113 ||
      codepoint == 0x2115 ||
      0x2119 <= codepoint && codepoint <= 0x211d ||
      codepoint == 0x2124 ||
      codepoint == 0x2126 ||
      codepoint == 0x2128 ||
      0x212a <= codepoint && codepoint <= 0x212d ||
      0x212f <= codepoint && codepoint <= 0x2131 ||
      0x2133 <= codepoint && codepoint <= 0x2139 ||
      0x213d <= codepoint && codepoint <= 0x213f ||
      0x2145 <= codepoint && codepoint <= 0x2149 ||
      0x2160 <= codepoint && codepoint <= 0x2183 ||
      0x2336 <= codepoint && codepoint <= 0x237a ||
      codepoint == 0x2395 ||
      0x249c <= codepoint && codepoint <= 0x24e9 ||
      0x3005 <= codepoint && codepoint <= 0x3007 ||
      0x3021 <= codepoint && codepoint <= 0x3029 ||
      0x3031 <= codepoint && codepoint <= 0x3035 ||
      0x3038 <= codepoint && codepoint <= 0x303c ||
      0x3041 <= codepoint && codepoint <= 0x3096 ||
      0x309d <= codepoint && codepoint <= 0x309f ||
      0x30a1 <= codepoint && codepoint <= 0x30fa ||
      0x30fc <= codepoint && codepoint <= 0x30ff ||
      0x3105 <= codepoint && codepoint <= 0x312c ||
      0x3131 <= codepoint && codepoint <= 0x318e ||
      0x3190 <= codepoint && codepoint <= 0x31b7 ||
      0x31f0 <= codepoint && codepoint <= 0x321c ||
      0x3220 <= codepoint && codepoint <= 0x3243 ||
      0x3260 <= codepoint && codepoint <= 0x327b ||
      0x327f <= codepoint && codepoint <= 0x32b0 ||
      0x32c0 <= codepoint && codepoint <= 0x32cb ||
      0x32d0 <= codepoint && codepoint <= 0x32fe ||
      0x3300 <= codepoint && codepoint <= 0x3376 ||
      0x337b <= codepoint && codepoint <= 0x33dd ||
      0x33e0 <= codepoint && codepoint <= 0x33fe ||
      0x3400 <= codepoint && codepoint <= 0x4db5 ||
      0x4e00 <= codepoint && codepoint <= 0x9fa5 ||
      0xa000 <= codepoint && codepoint <= 0xa48c ||
      0xac00 <= codepoint && codepoint <= 0xd7a3 ||
      0xd800 <= codepoint && codepoint <= 0xfa2d ||
      0xfa30 <= codepoint && codepoint <= 0xfa6a ||
      0xfb00 <= codepoint && codepoint <= 0xfb06 ||
      0xfb13 <= codepoint && codepoint <= 0xfb17 ||
      0xff21 <= codepoint && codepoint <= 0xff3a ||
      0xff41 <= codepoint && codepoint <= 0xff5a ||
      0xff66 <= codepoint && codepoint <= 0xffbe ||
      0xffc2 <= codepoint && codepoint <= 0xffc7 ||
      0xffca <= codepoint && codepoint <= 0xffcf ||
      0xffd2 <= codepoint && codepoint <= 0xffd7 ||
      0xffda <= codepoint && codepoint <= 0xffdc ||
      0x10300 <= codepoint && codepoint <= 0x1031e ||
      0x10320 <= codepoint && codepoint <= 0x10323 ||
      0x10330 <= codepoint && codepoint <= 0x1034a ||
      0x10400 <= codepoint && codepoint <= 0x10425 ||
      0x10428 <= codepoint && codepoint <= 0x1044d ||
      0x1d000 <= codepoint && codepoint <= 0x1d0f5 ||
      0x1d100 <= codepoint && codepoint <= 0x1d126 ||
      0x1d12a <= codepoint && codepoint <= 0x1d166 ||
      0x1d16a <= codepoint && codepoint <= 0x1d172 ||
      0x1d183 <= codepoint && codepoint <= 0x1d184 ||
      0x1d18c <= codepoint && codepoint <= 0x1d1a9 ||
      0x1d1ae <= codepoint && codepoint <= 0x1d1dd ||
      0x1d400 <= codepoint && codepoint <= 0x1d454 ||
      0x1d456 <= codepoint && codepoint <= 0x1d49c ||
      0x1d49e <= codepoint && codepoint <= 0x1d49f ||
      codepoint == 0x1d4a2 ||
      0x1d4a5 <= codepoint && codepoint <= 0x1d4a6 ||
      0x1d4a9 <= codepoint && codepoint <= 0x1d4ac ||
      0x1d4ae <= codepoint && codepoint <= 0x1d4b9 ||
      codepoint == 0x1d4bb ||
      0x1d4bd <= codepoint && codepoint <= 0x1d4c0 ||
      0x1d4c2 <= codepoint && codepoint <= 0x1d4c3 ||
      0x1d4c5 <= codepoint && codepoint <= 0x1d505 ||
      0x1d507 <= codepoint && codepoint <= 0x1d50a ||
      0x1d50d <= codepoint && codepoint <= 0x1d514 ||
      0x1d516 <= codepoint && codepoint <= 0x1d51c ||
      0x1d51e <= codepoint && codepoint <= 0x1d539 ||
      0x1d53b <= codepoint && codepoint <= 0x1d53e ||
      0x1d540 <= codepoint && codepoint <= 0x1d544 ||
      codepoint == 0x1d546 ||
      0x1d54a <= codepoint && codepoint <= 0x1d550 ||
      0x1d552 <= codepoint && codepoint <= 0x1d6a3 ||
      0x1d6a8 <= codepoint && codepoint <= 0x1d7c9 ||
      0x20000 <= codepoint && codepoint <= 0x2a6d6 ||
      0x2f800 <= codepoint && codepoint <= 0x2fa1d ||
      0xf0000 <= codepoint && codepoint <= 0xffffd ||
      0x100000 <= codepoint && codepoint <= 0x10fffd
  }

}