package com.github.mauricio.async.db.postgresql.sasl

import com.github.mauricio.async.db.exceptions.DatabaseException
import com.github.mauricio.async.db.postgresql.sasl.SaslEngine.SASLContext

class MissingAuthParamException(
  val isUsernameEmpty: Boolean,
  val ctx: Option[SASLContext],
  val password: Option[String]
) extends DatabaseException(
    s"Missing ${if (isUsernameEmpty) "username" else "password or SASL-context password=[%s] ctx=[%s]"}".format(
      password,
      ctx
    )
  )
