defmodule Ockam.Integration.Handshake.Test do
  use ExUnit.Case, async: false
  require Logger

  alias Ockam.Channel
  alias Ockam.Transport.Address
  alias Ockam.Transport.Socket
  alias Ockam.Vault.KeyPair

  setup context do
    if transport = context[:transport] do
      name = Map.fetch!(context, :transport_name)
      meta = [name: name]
      config = Map.get(context, :transport_config, [])
      pid = start_supervised!({transport, [meta, config]})
      {:ok, [pid: pid, config: config]}
    else
      {:ok, []}
    end
  end

  @tag transport: Ockam.Transport.TCP
  @tag transport_name: :tcp_4000
  @tag transport_config: [listen_address: "0.0.0.0", listen_port: 4000]
  @tag capture_log: false
  test "with C implementation as initiator", %{config: _config} do
    assert {:ok, _} = run_initiator!(["-a", "127.0.0.1", "-p", "4000"])
  end


  @tag initiator: true
  @tag listen_port: 5000
  test "with C implementation as responder", %{listen_port: port} do
    # Start server first
    assert {:ok, _} = run_responder!(["-a", "127.0.0.1", "-p", "5000"])

    {:ok, addr} = Address.new(:inet, :loopback, port)
    socket = Socket.new(:client, addr)

    s = KeyPair.new(:x25519)
    e = KeyPair.new(:x25519)
    rs = KeyPair.new(:x25519)
    re = KeyPair.new(:x25519)

    handshake_opts = %{protocol: "Noise_XX_25519_AESGCM_SHA256", s: s, e: e, rs: rs, re: re}
    assert {:ok, handshake} = Channel.handshake(:initiator, handshake_opts)
    assert {:ok, transport} = Socket.open(socket)
    assert {:ok, _chan, transport} = Channel.negotiate_secure_channel(handshake, transport)
    assert {:ok, _} = Socket.close(transport)
  end

  defp run_initiator!(args \\ []) when is_list(args) do
    invoke_test_executable!(["-i" | args])
  end

  defp run_responder!(args \\ []) when is_list(args) do
    invoke_test_executable!(["-r" | args])
  end

  defp invoke_test_executable!(args \\ []) when is_list(args) do
    this = self()
    spawn_link(fn ->
      Process.flag(:trap_exit, true)

      init_dir = Path.expand(Path.join([__DIR__, "..", "..", "..", "c", "_build"]))
      init_cmd = Path.join([init_dir, "Debug", "tests", "ockam_key_agreement_tests_xx_full"])
      port = Port.open({:spawn_executable, init_cmd}, [:binary, args: args])

      #{output, status} = System.cmd(init_cmd, args, cd: init_dir, stderr_to_stdout: true, into: IO.stream(:stdio, :line))
      send(this, :spawned)
      monitor_test_executable(this, port, <<>>)
    end)

    receive do
      :spawned ->
        {:ok, ""}

      {:ok, _output} = result ->
        result

      {:error, reason, output} ->
        Logger.warn("Captured Output:\n" <> output)
        {:error, reason}
    end
  end

  defp monitor_test_executable(parent, port, output) do
    receive do
      {^port, {:data, data}} ->
        monitor_test_executable(parent, port, output <> data)

      {^port, :closed} ->
        send(parent, {:ok, output})

      {:EXIT, ^port, reason} ->
        send(parent, {:error, reason, output})

      {:EXIT, ^parent, _} ->
        Port.close(port)
    end
  end
end
