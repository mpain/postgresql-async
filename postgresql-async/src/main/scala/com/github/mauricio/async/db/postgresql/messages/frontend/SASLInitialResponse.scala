package com.github.mauricio.async.db.postgresql.messages.frontend

import com.github.mauricio.async.db.postgresql.messages.backend.ServerMessage
import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.ClientFirstMessage

case class SASLInitialResponse(method: String, data: ClientFirstMessage) extends ClientMessage(ServerMessage.PasswordMessage)
