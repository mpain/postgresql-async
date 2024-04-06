package com.github.mauricio.async.db.postgresql.messages.backend

import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.ServerFirstMessage

case class AuthenticationSASLContinueMessage(msg: ServerFirstMessage) extends AuthenticationMessage
