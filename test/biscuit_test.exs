defmodule BiscuitTest do
  use ExUnit.Case

  test "creates valid keys" do
    private_key = Biscuit.keypair_new()
    public_key = Biscuit.keypair_to_public(private_key)

    assert String.length(private_key) == 64
    assert String.length(public_key) == 72
    assert String.starts_with?(public_key, "ed25")

    authority =
      Biscuit.create_authority(~S"""
user({user_id});
check if operation("read");
""", %{"user_id" => "1234"})

    token = Biscuit.builder_new()
      |> Biscuit.builder_add_block(authority)
      |> Biscuit.builder_build(private_key)

    request_comes_in = ~S[
// request-specific data
resource({res});
operation("write");
time(2021-12-21T20:00:00Z);

// server-side ACLs
right("1234", "resource1", "write");

// policy
allow if
  user($user_id),
  resource($res),
  operation($op),
  right($user_id, $res, $op);
    ]

    checker =
      Biscuit.create_authority(request_comes_in, %{
        "res" => "resource1",
      })

    # comibne token and checker, and print result

    IO.puts(token)
  end
end
