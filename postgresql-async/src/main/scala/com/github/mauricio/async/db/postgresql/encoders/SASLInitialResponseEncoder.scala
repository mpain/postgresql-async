package com.github.mauricio.async.db.postgresql.encoders

import com.github.mauricio.async.db.postgresql.messages.backend.ServerMessage
import com.github.mauricio.async.db.postgresql.messages.frontend.{ClientMessage, SASLInitialResponse}
import com.github.mauricio.async.db.postgresql.sasl.SaslEngine
import com.github.mauricio.async.db.util.ByteBufferUtils
import io.netty.buffer.{ByteBuf, Unpooled}

import java.nio.charset.Charset

class SASLInitialResponseEncoder(charset: Charset) extends Encoder {
  override def encode(message: ClientMessage): ByteBuf = {
    val msg = message.asInstanceOf[SASLInitialResponse]
    val data = SaslEngine.SaslHeader + msg.data.toScramMessage
    val buffer = Unpooled.buffer(1 + 4 + msg.method.length + 1 + 4 + data.length)
    buffer.writeByte(ServerMessage.PasswordMessage)
    buffer.writeInt(0)
    buffer.writeBytes(msg.method.getBytes(charset))
    buffer.writeByte(0)
    buffer.writeInt(data.length)
    buffer.writeBytes(data.getBytes(charset))

    ByteBufferUtils.writeLength(buffer)
    buffer
  }
}
