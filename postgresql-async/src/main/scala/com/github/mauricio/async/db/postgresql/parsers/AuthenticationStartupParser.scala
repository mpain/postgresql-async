/*
 * Copyright 2013 Maurício Linhares
 *
 * Maurício Linhares licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.github.mauricio.async.db.postgresql.parsers

import com.github.mauricio.async.db.exceptions.UnsupportedAuthenticationMethodException
import com.github.mauricio.async.db.postgresql.messages.backend._
import com.github.mauricio.async.db.postgresql.sasl.SaslEngine
import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.{ParseScramMessageOps, ServerFinalMessage, ServerFirstMessage}
import com.github.mauricio.async.db.util.ByteBufferUtils
import io.netty.buffer.{ByteBuf, Unpooled}

import java.nio.charset.Charset

object AuthenticationStartupParser extends MessageParser {

  val AuthenticationOk                = 0
  val AuthenticationKerberosV5        = 2
  val AuthenticationCleartextPassword = 3
  val AuthenticationMD5Password       = 5
  val AuthenticationSCMCredential     = 6
  val AuthenticationGSS               = 7
  val AuthenticationGSSContinue       = 8
  val AuthenticationSSPI              = 9
  val AuthenticationSASL              = 10
  val AuthenticationSASLContinue      = 11
  val AuthenticationSASLFinal         = 12

  override def parseMessage(b: ByteBuf): ServerMessage = {

    val authenticationType = b.readInt()

    authenticationType match {
      case AuthenticationOk                => AuthenticationOkMessage.Instance
      case AuthenticationCleartextPassword => AuthenticationChallengeCleartextMessage.Instance
      case AuthenticationMD5Password       =>
        val bytes = new Array[Byte](b.readableBytes())
        b.readBytes(bytes)
        new AuthenticationChallengeMD5(bytes)
      case AuthenticationSASL              =>
        val bytes = new Array[Byte](b.readableBytes())
        b.readBytes(bytes)
        AuthenticationSASLMessage(SaslEngine.parseSaslMethodList(bytes))
      case AuthenticationSASLContinue      =>
        val bytes = new Array[Byte](b.readableBytes())
        b.readBytes(bytes)

        val msg = new String(bytes).parseScramMessage[ServerFirstMessage] match {
          case Right(m)    => m
          case Left(cause) => throw new UnsupportedAuthenticationMethodException(cause)
        }
        AuthenticationSASLContinueMessage(msg)
      case AuthenticationSASLFinal         =>
        val bytes = new Array[Byte](b.readableBytes())
        b.readBytes(bytes)

        val msg = new String(bytes).parseScramMessage[ServerFinalMessage] match {
          case Right(m)    => m
          case Left(cause) => throw new UnsupportedAuthenticationMethodException(cause)
        }
        AuthenticationSASLFinalMessage(msg)
      case _                               =>
        throw new UnsupportedAuthenticationMethodException(authenticationType)

    }
  }
}
