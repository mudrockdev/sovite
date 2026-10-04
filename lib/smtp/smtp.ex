defmodule Sovite.SMTP do
  @moduledoc """
  SMTP (RFC 5321) building blocks.

    * `Sovite.SMTP.Reply` - reply codes, enhanced status codes, encoding
    * `Sovite.SMTP.Command` - command line parser
    * `Sovite.SMTP.DataDecoder` - streaming `DATA` decoder, smuggling-safe
    * `Sovite.SMTP.Server` - an SMTP server with a pluggable
      `Sovite.SMTP.Server.Handler`
  """
end
