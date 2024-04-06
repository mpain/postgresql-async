package com.github.mauricio.async.db.postgresql.messages.backend

case class AuthenticationSASLMessage(methods: Set[String]) extends AuthenticationMessage
