package com.github.mauricio.async.db.postgresql.messages.frontend

import com.github.mauricio.async.db.postgresql.messages.backend.ServerMessage
import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.ClientFinalMessage

case class SASLResponse(data: ClientFinalMessage) extends ClientMessage(ServerMessage.PasswordMessage)
