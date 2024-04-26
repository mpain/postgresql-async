package com.github.mauricio.async.db.postgresql.sasl

import com.github.mauricio.async.db.exceptions.DatabaseException
import com.github.mauricio.async.db.postgresql.sasl.ScramMessages.ServerFinalMessage

class InvalidFinalServerMessageProof(serverFinalMessage: ServerFinalMessage)
  extends DatabaseException(
    "Invalid server proof, authentication failed. Server final message: %s".format(serverFinalMessage.toScramMessage)
  )
