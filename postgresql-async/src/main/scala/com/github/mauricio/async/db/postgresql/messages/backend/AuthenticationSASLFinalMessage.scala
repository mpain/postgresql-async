package com.github.mauricio.async.db.postgresql.messages.backend

import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.ServerFinalMessage

case class AuthenticationSASLFinalMessage(msg: ServerFinalMessage) extends AuthenticationMessage
