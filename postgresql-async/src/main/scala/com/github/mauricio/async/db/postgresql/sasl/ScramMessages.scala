package com.github.mauricio.async.db.postgresql.sasl

import java.util.Base64
import scala.util.{Failure, Success, Try}

object ScramMessages {
  sealed trait ScramMessage
  case class ClientFirstMessage(user: String, nonce: String) extends ScramMessage
  case class ServerFirstMessage(nonce: String, salt: Array[Byte], iterations: Int) extends ScramMessage
  case class ClientFinalMessage(command: String, nonce: String, proof: Option[Array[Byte]]) extends ScramMessage
  case class ServerFinalMessage(serverProof: Array[Byte]) extends ScramMessage

  trait ScramMessageSerializer[T <: ScramMessage] {
    def scramMessage(source: T): String
  }

  implicit class ConvertScramMessageOps[T <: ScramMessage](val msg: T) extends AnyVal {
    def toScramMessage(implicit S: ScramMessageSerializer[T]): String = S.scramMessage(msg)
  }

  implicit val clientFirstMessageInstance: ScramMessageSerializer[ClientFirstMessage] =
    new ScramMessageSerializer[ClientFirstMessage] {
      override def scramMessage(m: ClientFirstMessage): String = s"n=${m.user},r=${m.nonce}"
    }

  implicit val clientFinalMessageInstance: ScramMessageSerializer[ClientFinalMessage] =
    new ScramMessageSerializer[ClientFinalMessage] {
      override def scramMessage(m: ClientFinalMessage): String =
        s"c=${m.command},r=${m.nonce}${m.proof.fold("")(p => s",p=${Base64.getEncoder.encodeToString(p)}")}"
    }

  implicit val serverFirstMessageInstance: ScramMessageSerializer[ServerFirstMessage] =
    new ScramMessageSerializer[ServerFirstMessage] {
      override def scramMessage(m: ServerFirstMessage): String =
        s"r=${m.nonce},s=${Base64.getEncoder.encodeToString(m.salt)},i=${m.iterations}"
    }

  implicit val serverFinalMessageInstance: ScramMessageSerializer[ServerFinalMessage] =
    new ScramMessageSerializer[ServerFinalMessage] {
      override def scramMessage(m: ServerFinalMessage): String = s"v=${Base64.getEncoder.encodeToString(m.serverProof)}"
    }

  trait ScramMessageParser[T <: ScramMessage] {
    def parse(s: String): Either[String, T]
  }

  implicit class ParseScramMessageOps(val s: String) extends AnyVal {
    def parseScramMessage[T <: ScramMessage]()(implicit P: ScramMessageParser[T]): Either[String, T] = P.parse(s)
  }

  private val SplitRegex = "^([nmrcsipve])(?:=([^,]+))?".r

  private def splitAndValidate(s: String, attributes: Set[Char]): Either[String, Map[Char, String]] =
    Try {
      s.split(',')
        .toList
        .filter(_.nonEmpty)
        .map {
          case SplitRegex(attr, value) if attributes.contains(attr.toCharArray.head) =>
            attr.toCharArray.head -> Option(value).getOrElse("")
          case s                                                                     =>
            throw new IllegalStateException(s"$s cannot be parsed")
        }
        .toMap
    } match {
      case Success(value)     => Right(value)
      case Failure(exception) => Left(exception.getMessage)
    }

  implicit val clientFirstMessageParser: ScramMessageParser[ClientFirstMessage] =
    new ScramMessageParser[ClientFirstMessage] {
      override def parse(source: String): Either[String, ClientFirstMessage] = source match {
        case s if s.startsWith("n,,") =>
          splitAndValidate(s, Set('n', 'r')).right.map(m => ClientFirstMessage(m('n'), m('r')))
        case other                    => Left(s"Bad input: $other")
      }
    }

  implicit val clientFinalMessageParser: ScramMessageParser[ClientFinalMessage] =
    new ScramMessageParser[ClientFinalMessage] {
      override def parse(source: String): Either[String, ClientFinalMessage] =
        splitAndValidate(source, Set('c', 'r', 'p')).right.map(m =>
          ClientFinalMessage(m('c'), m('r'), m.get('p').map(Base64.getDecoder.decode))
        )
    }

  implicit val serverFirstMessageParser: ScramMessageParser[ServerFirstMessage] =
    new ScramMessageParser[ServerFirstMessage] {
      override def parse(source: String): Either[String, ServerFirstMessage] =
        splitAndValidate(source, Set('r', 's', 'i')).right.map(m =>
          ServerFirstMessage(m('r'), Base64.getDecoder.decode(m('s')), m('i').toInt)
        )
    }

  implicit val serverFinalMessageParser: ScramMessageParser[ServerFinalMessage] =
    new ScramMessageParser[ServerFinalMessage] {
      override def parse(source: String): Either[String, ServerFinalMessage] =
        splitAndValidate(source, Set('v')).right.map(m => ServerFinalMessage(Base64.getDecoder.decode(m('v'))))
    }
}
