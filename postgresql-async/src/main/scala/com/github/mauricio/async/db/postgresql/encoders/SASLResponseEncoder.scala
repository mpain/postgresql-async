package com.github.mauricio.async.db.postgresql.encoders

import com.github.mauricio.async.db.postgresql.messages.backend.ServerMessage
import com.github.mauricio.async.db.postgresql.messages.frontend.{ClientMessage, SASLResponse}
import com.github.mauricio.async.db.util.ByteBufferUtils
import io.netty.buffer.{ByteBuf, Unpooled}

import java.nio.charset.Charset

class SASLResponseEncoder(charset: Charset) extends Encoder {
  override def encode(message: ClientMessage): ByteBuf = {
    val msg = message.asInstanceOf[SASLResponse]
    val data = msg.data.toScramMessage
    val buffer = Unpooled.buffer(1 + 4 + data.length)
    buffer.writeByte(ServerMessage.PasswordMessage)
    buffer.writeInt(0)
    buffer.writeBytes(data.getBytes(charset))

    ByteBufferUtils.writeLength(buffer)
    buffer
  }
}
