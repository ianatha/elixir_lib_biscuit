defmodule Biscuit do
  @moduledoc """
  Documentation for `Biscuit`.
  """

  use Rustler, otp_app: :biscuit, crate: "biscuit"

  @spec keypair_new() :: charlist()
  def keypair_new(), do: error()

  @spec keypair_to_public(charlist()) :: charlist()
  def keypair_to_public(_priv), do: error()

  @spec create_authority(charlist(), map()) :: charlist()
  def create_authority(_spec, _terms), do: error()

  def builder_new(), do: error()

  def builder_add_block(_builder, _authority), do: error()

  def builder_build(_builder, _priv), do: error()

  defp error(), do: :erlang.nif_error(:nif_not_loaded)
end
