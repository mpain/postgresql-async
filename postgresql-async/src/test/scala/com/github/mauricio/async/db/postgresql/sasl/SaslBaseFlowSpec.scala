package com.github.mauricio.async.db.postgresql.sasl

import com.github.mauricio.async.db.postgresql.sasl.SaslEngine._
import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.{ClientFinalMessage, ClientFirstMessage, ParseScramMessageOps, ServerFinalMessage, ServerFirstMessage}
import SaslBaseFlowSpec.PBKDF2_KEY_LENGTH
import org.specs2.mutable.Specification

import java.security.MessageDigest
import java.util.Base64
import scala.annotation.tailrec

object SaslBaseFlowSpec {
  val PBKDF2_KEY_LENGTH: Int   = MessageDigest.getInstance("SHA-256").getDigestLength
}

class SaslBaseFlowSpec extends Specification {
  /*
   This is a simple example of a SCRAM-SHA-256 authentication exchange
   when the client doesn't support channel bindings.  The username
   'user' and password 'pencil' are being used.

   C: n,,n=user,r=rOprNGfwEbeRWgbNEkqO
   S: r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096
   C: c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
   S: v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=
   */

  def hiAlt(data: String, salt: Array[Byte], iterations: Int): Array[Byte] = {
    val bytes = data.getBytes

    @tailrec
    def step(acc: Array[Byte], prev: Array[Byte], remaining: Int): Array[Byte] =
      remaining match {
        case i if i == 0          => acc
        case i if i == iterations =>
          val u1 = hmac(bytes, salt ++ Array[Byte](0x00.toByte, 0x00.toByte, 0x00.toByte, 0x01.toByte))
          step(u1, u1, i - 1)
        case i                    =>
          val ui = hmac(bytes, prev)
          val hi = xor(acc, ui)
          step(hi, ui, i - 1)
      }
    step(new Array[Byte](PBKDF2_KEY_LENGTH), new Array[Byte](PBKDF2_KEY_LENGTH), iterations)
  }

  "An engine" should {
    "should generate random nonces" in {
      (0 until 1000).foreach { i =>
        val res = random(20)
        println(s"Iteration: $i => $res")
        res.contains(",") !== true
      }
      ok
    }

    "parse a client-first message" in {
      val message = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
      val result  = message.parseScramMessage[ClientFirstMessage]
      println(result)
      ok
    }

    "parse a client-final message" in {
      val message =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
      val result  = message.parseScramMessage[ClientFinalMessage]
      println(result)
      ok
    }

    "parse a server-first message" in {
      val message = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
      val result  = message.parseScramMessage[ServerFirstMessage]
      println(result)
      ok
    }

    "parse a server-final message" in {
      val message = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
      val result  = message.parseScramMessage[ServerFinalMessage]
      println(result)
      ok
    }

    "calculate a Hi function" in {
      val clientFirst       = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
        .parseScramMessage[ClientFirstMessage]
        .right
        .get
      val serverFirst       = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
        .parseScramMessage[ServerFirstMessage]
        .right
        .get
      val clientFinal       =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
          .parseScramMessage[ClientFinalMessage]
          .right
          .get
      val serverFinal       = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=".parseScramMessage[ServerFinalMessage].right.get
      val saltedPassword    = hi("pencil", serverFirst.salt, serverFirst.iterations)
      println(s"SaltedPassword: ${toHex(saltedPassword)}")
      val saltedPasswordAlt = hiAlt("pencil", serverFirst.salt, serverFirst.iterations)
      println(s"SaltedPasswordAlt: ${toHex(saltedPasswordAlt)}")
      val clientKey         = hmac(saltedPasswordAlt, "Client Key".getBytes)
      println(s"ClientKey: ${toHex(clientKey)}")
      val storedKey         = hash(clientKey)
      println(s"StoredKey: ${toHex(storedKey)}")

      val clientFinalWork = ClientFinalMessage("biws", serverFirst.nonce, None)
      val authMessage     = List(
        clientFirst.toScramMessage,
        serverFirst.toScramMessage,
        clientFinalWork.toScramMessage
      ).mkString(",")

      println(s"AuthMessage: $authMessage")
      val clientSignature = hmac(storedKey, authMessage.getBytes)
      println(s"ClientSignature: ${toHex(clientSignature)}")
      val clientProof     = xor(clientKey, clientSignature)

      println(s"ClientProof: ${Base64.getEncoder.encodeToString(clientProof)}")
      val clientFinalPrepared = clientFinalWork.copy(proof = Option(clientProof))
      clientFinalPrepared.toScramMessage === clientFinal.toScramMessage
      println(s"ClientFinalMessage: ${clientFinalPrepared.toScramMessage}")

      val validate = xor(clientProof, clientSignature)

      println(s"Validate: ${Base64.getEncoder.encodeToString(validate)}")
      println(s"ValidateHex: ${toHex(validate)}")
      val validate2 = xor(clientProof, clientKey)
      println(s"Validate2: ${Base64.getEncoder.encodeToString(validate2)}")
      println(s"ValidateHex2: ${toHex(validate2)}")

      val serverKey       = hmac(saltedPassword, "Server Key".getBytes)
      val serverSignature = hmac(serverKey, authMessage.getBytes)
      println(s"ServerSignature: ${Base64.getEncoder.encodeToString(serverSignature)}")

      serverSignature === serverFinal.serverProof
    }

  }

}
