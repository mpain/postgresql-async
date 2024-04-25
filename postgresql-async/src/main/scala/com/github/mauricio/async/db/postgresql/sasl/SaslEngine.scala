package com.github.mauricio.async.db.postgresql.sasl

import com.github.mauricio.async.db.exceptions.DatabaseException
import com.github.mauricio.async.db.postgresql.messages.backend.{
  AuthenticationSASLContinueMessage,
  AuthenticationSASLFinalMessage,
  AuthenticationSASLMessage
}
import com.github.mauricio.async.db.postgresql.messages.frontend.{SASLInitialResponse, SASLResponse}
import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.{ClientFinalMessage, ClientFirstMessage}
import com.github.mauricio.async.db.util.{ByteBufferUtils, Log}
import io.netty.buffer.{ByteBuf, Unpooled}

import java.nio.charset.Charset
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.spec.{PBEKeySpec, SecretKeySpec}
import javax.crypto.{Mac, SecretKeyFactory}
import scala.annotation.tailrec
import scala.util.Random

/**
 * Engine contains definition of calculation SASL mechanism which is used for SCRAM
 * @see [[https://datatracker.ietf.org/doc/html/rfc5802 RFC-5802]]
 *      [[https://www.improving.com/thoughts/making-sense-of-scram-sha-256-authentication-in-mongodb Article about SCRAM]]
 *      for more info about SCRAM
 */
object SaslEngine {

  val SaslHeader      = "n,,"
  private val SaslNonceLength = 20
  private val SaslMechanism   = "SCRAM-SHA-256"

  case class SASLContext(firstMsg: ClientFirstMessage, serverProof: Option[String])

  private val HashAlg = "SHA-256"
  private val MacAlg  = "HmacSHA256"

  private val Pbkdf2Alg: String    = "PBKDF2WithHmacSHA256"
  private val Pbkdf2KeyLength: Int = MessageDigest.getInstance(HashAlg).getDigestLength

  private val log = Log.getByName(this.getClass.getName)

  private[sasl] def hi(password: String, salt: Array[Byte], iterations: Int): Array[Byte] = {
    val spec = new PBEKeySpec(password.toCharArray, salt, iterations, Pbkdf2KeyLength * 8)
    val skf  = SecretKeyFactory.getInstance(Pbkdf2Alg)
    val key  = skf.generateSecret(spec)
    key.getEncoded
  }

  private[sasl] def hmac(key: Array[Byte], str: Array[Byte]): Array[Byte] = {
    val mac = Mac.getInstance(MacAlg)
    mac.init(new SecretKeySpec(key, MacAlg))
    mac.doFinal(str)
  }

  private[sasl] def hash(bytes: Array[Byte]): Array[Byte] = MessageDigest.getInstance(HashAlg).digest(bytes)

  private[sasl] def xor(right: Array[Byte], left: Array[Byte]): Array[Byte] =
    right.zip(left).map(t => (t._1 ^ t._2).toByte)

  private[sasl] def random(length: Int): String = {
    val random = new Random()
    val result = new Array[Byte](length)
    (0 until length).foreach { i =>
      val data = (random.nextInt(127 - 33) + 33).toByte
      result.update(i, if (data == ','.toByte) 126.toByte else data)
    }
    new String(result)
  }

  private[sasl] def toHex(bytes: Array[Byte]): String = bytes.map(_.formatted("%02x")).mkString

  private def debug(msg: => String): Unit = if (log.isDebugEnabled) log.debug(msg)

  def parseSaslMethodList(bytes: Array[Byte]): Set[String] = {
    @tailrec
    def step(acc: List[String], buf: ByteBuf): Set[String] =
      ByteBufferUtils.readCString(buf, Charset.defaultCharset()) match {
        case str if str.isEmpty => acc.toSet
        case str                => step(str :: acc, buf)
      }

    step(Nil, Unpooled.copiedBuffer(bytes))
  }

  def createSaslInitialResponse(msg: AuthenticationSASLMessage, user: String): (SASLContext, SASLInitialResponse) = {
    if (!msg.methods.contains(SaslMechanism)) {
      throw new DatabaseException(s"Unsupported SASL methods: ${msg.methods}")
    }

    val nonce    = random(SaslNonceLength)
    val firstMsg = ClientFirstMessage(user, nonce)
    val ctx      = SASLContext(firstMsg, None)
    (ctx, SASLInitialResponse(SaslMechanism, firstMsg))
  }

  def createSaslResponse(
    ctx: SASLContext,
    msg: AuthenticationSASLContinueMessage,
    password: String
  ): (SASLContext, SASLResponse) = {
    val serverFirst = msg.msg

    if (!serverFirst.nonce.startsWith(ctx.firstMsg.nonce)) {
      throw new DatabaseException("bad incoming nonce")
    }

    val saltedPassword = hi(SaslPrep.saslPrepStored(password), serverFirst.salt, serverFirst.iterations)
    debug(s"SaltedPassword: ${toHex(saltedPassword)}")
    val clientKey      = hmac(saltedPassword, "Client Key".getBytes)
    debug(s"ClientKey: ${toHex(clientKey)}")
    val storedKey      = hash(clientKey)
    debug(s"StoredKey: ${toHex(storedKey)}")

    val clientFinalWork = ClientFinalMessage("biws", serverFirst.nonce, None)
    val authMessage     = List(
      ctx.firstMsg.toScramMessage,
      serverFirst.toScramMessage,
      clientFinalWork.toScramMessage
    ).mkString(",")

    debug(s"AuthMessage: $authMessage")
    val clientSignature = hmac(storedKey, authMessage.getBytes)
    debug(s"ClientSignature: ${toHex(clientSignature)}")
    val clientProof     = xor(clientKey, clientSignature)

    debug(s"ClientProof: ${Base64.getEncoder.encodeToString(clientProof)}")
    val clientFinalMsg = clientFinalWork.copy(proof = Option(clientProof))
    debug(s"ClientFinalMessage: ${clientFinalMsg.toScramMessage}")

    val serverKey   = hmac(saltedPassword, "Server Key".getBytes)
    val serverProof = Base64.getEncoder.encodeToString(hmac(serverKey, authMessage.getBytes))
    debug(s"ServerProof: $serverProof")

    (ctx.copy(serverProof = Option(serverProof)), SASLResponse(clientFinalMsg))
  }

  def validateFinalMessageProof(ctx: SASLContext, finalMessage: AuthenticationSASLFinalMessage): Boolean =
    ctx.serverProof.exists { ctxServerProof =>
      val serverFinalMessageProof = Base64.getEncoder.encodeToString(finalMessage.msg.serverProof)
      debug(s"ServerProof on client side: $ctxServerProof, ServerProof from server side in final message: $serverFinalMessageProof")
      finalMessage.msg.serverProof.nonEmpty && ctxServerProof == serverFinalMessageProof
    }
}
